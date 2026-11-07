# -*- coding: utf-8 -*-
"""OmniReverse Granular Engine (granular_engine.py)
Provides symbol, single-address, disassembly, cross-reference, and single-class inspection
across PE, ELF (Linux/Android), Mach-O (macOS/iOS), and APK/DEX binaries.
"""

from __future__ import annotations

import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from omni_config import get_jadx_cmd, is_safe_subpath, safe_read_binary, safe_zip_read

try:
    import pefile
except ImportError:
    pefile = None

try:
    import capstone
except ImportError:
    capstone = None

_CLASS_QUERY_RE = re.compile(r"^[A-Za-z0-9_.$]{1,180}$")


def _calc_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    total = len(buf)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def _inspect_elf_or_macho(data: bytes, target_name: str) -> dict[str, Any] | None:
    """Cross-platform header & section parser for Linux/Android ELF and macOS/iOS Mach-O."""
    if len(data) >= 64 and data[:4] == b"\x7fELF":
        is_64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        e_machine = struct.unpack(endian + "H", data[18:20])[0]
        arch_map = {0x3E: "x64", 0x03: "x86", 0xB7: "arm64", 0x28: "arm"}
        arch = arch_map.get(e_machine, f"elf_machine_0x{e_machine:x}")
        if is_64:
            e_entry, e_phoff, e_shoff = struct.unpack(endian + "QQQ", data[24:48])
            e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + "HHH", data[58:64])
        else:
            e_entry, e_phoff, e_shoff = struct.unpack(endian + "III", data[24:36])
            e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + "HHH", data[46:52])

        sections = []
        shstrtab = b""
        if e_shoff and e_shentsize and e_shstrndx < e_shnum:
            str_hdr_off = e_shoff + e_shstrndx * e_shentsize
            if str_hdr_off + e_shentsize <= len(data):
                if is_64:
                    sh_off, sh_sz = struct.unpack(endian + "QQ", data[str_hdr_off + 24 : str_hdr_off + 40])
                else:
                    sh_off, sh_sz = struct.unpack(endian + "II", data[str_hdr_off + 16 : str_hdr_off + 24])
                if sh_off + sh_sz <= len(data):
                    shstrtab = data[sh_off : sh_off + sh_sz]

        for idx in range(min(e_shnum, 64)):
            off = e_shoff + idx * e_shentsize
            if off + e_shentsize > len(data):
                break
            sh_name_idx = struct.unpack(endian + "I", data[off : off + 4])[0]
            if is_64:
                sh_addr, sh_offset, sh_size = struct.unpack(endian + "QQQ", data[off + 16 : off + 40])
            else:
                sh_addr, sh_offset, sh_size = struct.unpack(endian + "III", data[off + 12 : off + 24])
            sname = ""
            if sh_name_idx < len(shstrtab):
                end = shstrtab.find(b"\x00", sh_name_idx)
                sname = shstrtab[sh_name_idx : (end if end != -1 else sh_name_idx + 32)].decode("latin1", errors="ignore")
            sec_slice = data[sh_offset : min(len(data), sh_offset + sh_size)] if sh_offset < len(data) else b""
            sections.append({
                "name": sname or f"sec_{idx}",
                "virtual_address": hex(sh_addr),
                "virtual_size": hex(sh_size),
                "raw_size": sh_size,
                "entropy": _calc_entropy(sec_slice),
            })

        return {
            "target": target_name,
            "format": "ELF",
            "architecture": arch,
            "image_base": "0x0",
            "entry_point": hex(e_entry),
            "sections": sections,
            "export_count": 0,
            "exports": [],
            "import_modules": [],
            "imports": {},
        }

    # Mach-O 64-bit / 32-bit / Universal Fat Binary (macOS / iOS)
    if len(data) >= 32:
        magic = struct.unpack("<I", data[:4])[0]
        if magic in (0xFEEDFACF, 0xFEEDFACE, 0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA, 0xCAFEBABE):
            is_fat = magic in (0xBEBAFECA, 0xCAFEBABE)
            arch = "universal_fat" if is_fat else ("x64/arm64" if magic in (0xFEEDFACF, 0xCFFAEDFE) else "32-bit")
            return {
                "target": target_name,
                "format": "Mach-O",
                "architecture": arch,
                "image_base": "0x100000000",
                "entry_point": "0x0",
                "sections": [{"name": "__TEXT", "virtual_address": "0x100000000", "virtual_size": hex(len(data)), "raw_size": len(data), "entropy": _calc_entropy(data)}],
                "export_count": 0,
                "exports": [],
                "import_modules": [],
                "imports": {},
            }
    return None


def disassemble_bytes_at(
    target_path: str,
    offset_or_va: int,
    is_va: bool = True,
    arch: str = "x64",
    instruction_count: int = 25,
) -> dict[str, Any]:
    """Disassembles instructions at a given Virtual Address (VA) or raw file offset."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Hedef dosya bulunamadi: {target_path}"}
    if not capstone:
        return {"error": "Capstone kutuphanesi yuklu degil."}

    instruction_count = max(1, min(int(instruction_count), 500))
    arch_mode_map = {
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    }
    cs_arch, cs_mode = arch_mode_map.get(arch.lower(), (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False

    try:
        file_size = os.path.getsize(target_path)
        if file_size == 0:
            return {"error": "Dosya bos (0 bayt)."}

        file_offset: int | None = int(offset_or_va)
        display_address = int(offset_or_va)

        if is_va:
            with open(target_path, "rb") as f:
                magic = f.read(4)
            if magic[:2] == b"MZ" and pefile:
                data = safe_read_binary(target_path)
                pe = None
                try:
                    pe = pefile.PE(data=data, fast_load=True)
                    image_base = pe.OPTIONAL_HEADER.ImageBase
                    rva = offset_or_va - image_base if offset_or_va >= image_base else offset_or_va
                    if rva < 0:
                        return {"error": f"Gecersiz negatif RVA: {hex(rva)}"}
                    file_offset = pe.get_offset_from_rva(rva)
                    if file_offset is None:
                        return {"error": f"RVA/VA 0x{offset_or_va:X} hicbir eslenmis PE bolumune karsilik gelmiyor."}
                    display_address = image_base + rva
                except Exception as exc:
                    return {"error": f"PE RVA cozumleme hatasi: {exc}"}
                finally:
                    if pe is not None:
                        pe.close()

        if file_offset is None or file_offset < 0 or file_offset >= file_size:
            return {"error": f"Gecersiz offset/adres: 0x{offset_or_va:X} (Dosya boyutu: {file_size} byte)"}

        read_len = instruction_count * 16
        with open(target_path, "rb") as f:
            f.seek(file_offset)
            chunk = f.read(read_len)

        instructions = []
        for i in md.disasm(chunk, display_address):
            instructions.append({
                "address": f"0x{i.address:08X}",
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "bytes": i.bytes.hex(),
                "size": i.size,
            })
            if len(instructions) >= instruction_count:
                break

        formatted_asm = "\n".join([f"{ins['address']}:  {ins['mnemonic']:<8} {ins['op_str']}" for ins in instructions])
        return {
            "target": os.path.basename(target_path),
            "base_address": f"0x{display_address:X}",
            "file_offset": f"0x{file_offset:X}",
            "arch": arch,
            "count": len(instructions),
            "instructions": instructions,
            "asm_preview": formatted_asm,
        }
    except Exception as e:
        return {"error": f"Disassembly hatasi: {str(e)}"}


def inspect_pe_symbols(target_path: str, raw_data: bytes | None = None) -> dict[str, Any]:
    """Inspects PE/DLL, ELF, or Mach-O imports, exports, architecture, and section metadata."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    try:
        data = raw_data if raw_data is not None else safe_read_binary(target_path)
    except Exception as e:
        return {"error": str(e)}

    non_pe = _inspect_elf_or_macho(data, os.path.basename(target_path))
    if non_pe is not None:
        return non_pe

    if not pefile:
        return {"error": "pefile kutuphanesi mevcut degil."}

    pe = None
    try:
        pe = pefile.PE(data=data)
        machine_map = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64", 0x01C0: "arm"}
        arch = machine_map.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
        image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        sections = []
        for s in pe.sections:
            name = s.Name.decode("latin1", errors="ignore").strip("\x00")
            sections.append({
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": hex(s.Misc_VirtualSize),
                "raw_size": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 3),
            })

        imports = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("latin1", errors="ignore") if entry.dll else "unknown.dll"
                func_list = []
                for imp in entry.imports[:50]:
                    fname = imp.name.decode("latin1", errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    func_list.append({"name": fname, "address": hex(imp.address) if imp.address else "0x0"})
                imports[dll_name] = func_list

        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:100]:
                ename = exp.name.decode("latin1", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                exports.append({
                    "name": ename,
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    "ordinal": exp.ordinal,
                })

        return {
            "target": os.path.basename(target_path),
            "format": "PE",
            "architecture": arch,
            "image_base": image_base,
            "entry_point": entry_point,
            "sections": sections,
            "export_count": len(exports),
            "exports": exports,
            "import_modules": list(imports.keys()),
            "imports": imports,
        }
    except Exception as e:
        return {"error": f"PE sembol ayristirma hatasi: {str(e)}"}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def inspect_android_class(apk_or_dex_path: str, class_query: str) -> dict[str, Any]:
    """Decompiles a single Java/Kotlin class via JADX CLI with isolated temp dirs and pure-Python DEX fallback."""
    if not apk_or_dex_path or not os.path.isfile(apk_or_dex_path):
        return {"error": f"APK/DEX dosyasi bulunamadi: {apk_or_dex_path}"}

    clean_query = (class_query or "").strip()
    if clean_query.startswith("-") or not _CLASS_QUERY_RE.fullmatch(clean_query):
        return {"error": f"Gecersiz sinif sorgusu formati: {class_query!r}"}

    jadx_cmd = get_jadx_cmd()
    if jadx_cmd is not None:
        try:
            with tempfile.TemporaryDirectory(prefix="omni_jadx_") as tmp_out:
                tmp_dir = Path(tmp_out).resolve()
                cmd = [*jadx_cmd, "--single-class", clean_query, "-d", str(tmp_dir), os.path.abspath(apk_or_dex_path)]
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=35,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
                class_rel = clean_query.replace(".", "/") + ".java"
                target_java = (tmp_dir / "sources" / class_rel).resolve()
                if not (is_safe_subpath(target_java, tmp_dir) and target_java.is_file()):
                    matches = [m for m in tmp_dir.rglob("*.java") if is_safe_subpath(m, tmp_dir)]
                    target_java = matches[0] if matches else target_java

                if is_safe_subpath(target_java, tmp_dir) and target_java.is_file():
                    code = target_java.read_text(encoding="utf-8", errors="replace")
                    return {
                        "class_name": clean_query,
                        "engine": "jadx",
                        "found": True,
                        "code": code[:20000],
                    }
        except Exception:
            pass

    # Pure-Python DEX descriptor/string inspection fallback when JADX CLI is unavailable
    try:
        descriptor = "L" + clean_query.replace(".", "/") + ";"
        short_name = clean_query.split(".")[-1]
        dex_blobs: list[bytes] = []
        if zipfile.is_zipfile(apk_or_dex_path):
            with zipfile.ZipFile(apk_or_dex_path, "r") as zf:
                for n in [m for m in zf.namelist() if m.endswith(".dex")][:8]:
                    dex_blobs.append(safe_zip_read(zf, n))
        else:
            dex_blobs.append(safe_read_binary(apk_or_dex_path))

        related_strings: list[str] = []
        found_desc = False
        for blob in dex_blobs:
            if descriptor.encode("utf-8") in blob or short_name.encode("utf-8") in blob:
                found_desc = True
                for m in re.findall(rb"[\x20-\x7e]{4,100}", blob):
                    s = m.decode("latin1", errors="ignore")
                    if short_name in s or clean_query.replace(".", "/") in s:
                        if s not in related_strings:
                            related_strings.append(s)
                        if len(related_strings) >= 40:
                            break

        if found_desc:
            pseudo = [
                f"// Pure-Python DEX Bytecode Descriptor Reconstruction for {clean_query}",
                f"// Descriptor: {descriptor}",
                f"public class {short_name} {{",
            ]
            for rs in related_strings[:30]:
                pseudo.append(f"    // Symbol/Ref: {rs}")
            pseudo.append("}")
            return {
                "class_name": clean_query,
                "engine": "pure_python_dex_fallback",
                "found": True,
                "code": "\n".join(pseudo),
            }
        return {"class_name": clean_query, "found": False, "message": "Sinif DEX havuzunda bulunamadi."}
    except Exception as e:
        return {"error": f"Android sinif ayristirma hatasi: {str(e)}"}
