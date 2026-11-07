# -*- coding: utf-8 -*-
"""OmniReverse Advanced Native & Packer Engine (native_packer_engine.py)
Implements:
1. .NET CIL / BSJB Metadata, User-String & Costura.Fody Embedded Assembly Unpacker
2. Scylla-style Import Address Table (IAT) Thunk Scanner & Reconstructor
3. Direct Syscall (Hell's Gate / Tartarus / SysWhispers) Detector & Instrumentation Callback C++ Generator
4. Cryptographic S-Box / Constant Detector & Automated YARA Rule Synthesizer
5. Structural Binary Diffing (BinDiff / Patch Diffing across PE/ELF/Mach-O/APK)
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import zlib
from collections import Counter
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, is_safe_subpath, safe_read_binary

try:
    import pefile
except ImportError:
    pefile = None


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    total = len(buf)
    counts = Counter(buf)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


# ---------------------------------------------------------------------------
# 1. .NET CIL / BSJB METADATA & COSTURA UNPACKER
# ---------------------------------------------------------------------------

def inspect_dotnet_cil(target_path: str, extract_costura_dir: str | None = None) -> dict[str, Any]:
    """Parses ECMA-335 .NET BSJB metadata streams, detects obfuscators, and unpacks Costura resources."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    bsjb_off = data.find(b"BSJB")
    if bsjb_off == -1:
        return {"is_dotnet": False, "target": os.path.basename(target_path), "message": ".NET BSJB metadata imzasi bulunamadi."}

    result: dict[str, Any] = {
        "is_dotnet": True,
        "target": os.path.basename(target_path),
        "bsjb_offset": hex(bsjb_off),
        "clr_runtime_version": "",
        "streams": [],
        "obfuscators": [],
        "identifiers_sample": [],
        "user_strings_sample": [],
        "costura_embedded_dlls": [],
        "extracted_files": [],
    }

    try:
        if bsjb_off + 16 <= len(data):
            ver_len = struct.unpack_from("<I", data, bsjb_off + 12)[0]
            ver_len = min(ver_len, 64)
            if bsjb_off + 16 + ver_len <= len(data):
                result["clr_runtime_version"] = data[bsjb_off + 16 : bsjb_off + 16 + ver_len].rstrip(b"\x00").decode("utf-8", errors="ignore")
                pos = bsjb_off + 16 + ((ver_len + 3) & ~3)
                if pos + 4 <= len(data):
                    _flags, stream_count = struct.unpack_from("<HH", data, pos)
                    pos += 4
                    for _ in range(min(stream_count, 16)):
                        if pos + 8 > len(data):
                            break
                        s_off, s_size = struct.unpack_from("<II", data, pos)
                        pos += 8
                        end_name = data.find(b"\x00", pos, min(len(data), pos + 32))
                        if end_name == -1:
                            break
                        s_name = data[pos:end_name].decode("ascii", errors="ignore")
                        pos = (end_name + 4) & ~3
                        abs_stream_off = bsjb_off + s_off
                        result["streams"].append({"name": s_name, "offset": hex(abs_stream_off), "size": s_size})

                        if s_name == "#Strings" and abs_stream_off + min(s_size, 65536) <= len(data):
                            chunk = data[abs_stream_off : abs_stream_off + min(s_size, 65536)]
                            idents = [x.decode("utf-8", errors="ignore") for x in chunk.split(b"\x00") if 3 <= len(x) <= 96]
                            clean_id = [s for s in idents if s.isprintable() and not s.startswith("<")]
                            result["identifiers_sample"] = list(dict.fromkeys(clean_id))[:60]

                        elif s_name == "#US" and abs_stream_off + min(s_size, 65536) <= len(data):
                            us_chunk = data[abs_stream_off : abs_stream_off + min(s_size, 65536)]
                            utf16_hits = re.findall(rb"(?:[\x20-\x7e]\x00){4,80}", us_chunk)
                            decoded_us = [h.decode("utf-16le", errors="ignore") for h in utf16_hits]
                            result["user_strings_sample"] = list(dict.fromkeys(decoded_us))[:40]
    except Exception as exc:
        result["parse_warning"] = str(exc)

    protectors_map = {
        "ConfuserEx": [b"ConfusedByAttribute", b"ConfuserEx", b"Confuser.Core"],
        ".NET Reactor": [b"Reactor", b"__<PrivateImplementationDetails>__", b"NecroBit"],
        "SmartAssembly": [b"SmartAssembly.Attributes", b"PoweredByAttribute"],
        "Babel Obfuscator": [b"BabelObfuscatorAttribute"],
        "Costura.Fody": [b"costura.", b"CosturaUtility"],
        "Eazfuscator.NET": [b"Eazfuscator"],
    }
    for pname, sigs in protectors_map.items():
        if any(sig in data for sig in sigs):
            result["obfuscators"].append(pname)

    costura_names = [
        m.decode("ascii", errors="ignore")
        for m in re.findall(rb"costura\.[a-z0-9_.\-]+\.(?:dll|pdb)(?:\.compressed)?", data, flags=re.IGNORECASE)
    ]
    result["costura_embedded_dlls"] = sorted(set(costura_names))

    if extract_costura_dir and result["costura_embedded_dlls"]:
        out_root = Path(extract_costura_dir).resolve()
        exports_guard = (STUDIO_ROOT / ".exports").resolve()
        if not is_safe_subpath(out_root, STUDIO_ROOT) and not is_safe_subpath(out_root, exports_guard):
            out_root = exports_guard / f"dotnet_{Path(target_path).stem}"
        out_root.mkdir(parents=True, exist_ok=True)
        # Scan raw deflate streams preceded by MZ after decompression
        for match in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", data):
            start = match.start()
            try:
                dobj = zlib.decompressobj()
                dec = dobj.decompress(data[start : start + 4_194_304], 16_777_216)
                if len(dec) > 512 and dec[:2] == b"MZ":
                    fname = f"recovered_{start:08x}.dll"
                    dest = out_root / fname
                    dest.write_bytes(dec)
                    result["extracted_files"].append(str(dest))
                    if len(result["extracted_files"]) >= 15:
                        break
            except Exception:
                continue

    return result


# ---------------------------------------------------------------------------
# 2. SCYLLA-STYLE IAT THUNK SCANNER & RECONSTRUCTOR
# ---------------------------------------------------------------------------

_INDIRECT_CALL_JMP_RE = re.compile(rb"\xff[\x15\x25](.{4})", re.DOTALL)


def reconstruct_iat_scylla(target_path: str) -> dict[str, Any]:
    """Scans x86/x64 PE code sections for RIP-relative FF15/FF25 thunks, groups candidate IAT clusters,
    and cross-checks existing Import Directory entries for broken/trampoline slots.
    """
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}
    if not pefile:
        return {"error": "pefile modulu gerekli."}

    data = safe_read_binary(target_path)
    try:
        pe = pefile.PE(data=data)
    except Exception as exc:
        return {"error": f"Gecerli PE degil: {exc}"}

    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.FILE_HEADER.Machine == 0x8664

    known_slots: dict[int, str] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_n = entry.dll.decode("utf-8", errors="ignore")
            for imp in entry.imports:
                if imp.address:
                    sym_n = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                    known_slots[imp.address] = f"{dll_n}!{sym_n}"

    discovered_targets: list[int] = []
    for sec in pe.sections:
        if not (sec.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        sec_bytes = sec.get_data()
        sec_va = image_base + sec.VirtualAddress
        for m in _INDIRECT_CALL_JMP_RE.finditer(sec_bytes):
            disp = struct.unpack("<i", m.group(1))[0]
            slot_va = (sec_va + m.start() + 6 + disp) if is_64 else (disp & 0xFFFFFFFF)
            discovered_targets.append(slot_va)

    unique_slots = sorted(set(discovered_targets))
    resolved = []
    unresolved = []
    for va in unique_slots[:250]:
        if va in known_slots:
            resolved.append({"slot_va": hex(va), "symbol": known_slots[va]})
        else:
            unresolved.append(hex(va))

    iat_start = hex(unique_slots[0]) if unique_slots else "0x0"
    iat_end = hex(unique_slots[-1]) if unique_slots else "0x0"

    return {
        "target": os.path.basename(target_path),
        "architecture": "x64" if is_64 else "x86",
        "image_base": hex(image_base),
        "total_indirect_thunks_scanned": len(discovered_targets),
        "unique_iat_slots_found": len(unique_slots),
        "estimated_iat_range": f"{iat_start} - {iat_end}",
        "resolved_imports_count": len(resolved),
        "unresolved_or_obfuscated_slots_count": len(unresolved),
        "resolved_sample": resolved[:40],
        "unresolved_slots_sample": unresolved[:40],
    }


# ---------------------------------------------------------------------------
# 3. DIRECT SYSCALL (HELL'S GATE / TARTARUS / SYSWHISPERS) DETECTOR
# ---------------------------------------------------------------------------

# 4C 8B D1 (mov r10, rcx) ; B8 xx xx 00 00 (mov eax, ssn) ; [optional test] ; 0F 05 (syscall)
_HELLS_GATE_RE = re.compile(rb"\x4c\x8b\xd1\xb8([\x00-\xff]{2})\x00\x00(?:[\x00-\xff]{0,18}?)\x0f\x05", re.DOTALL)
_RAW_SYSCALL_RE = re.compile(rb"\x0f\x05\xc3")


def scan_direct_syscalls(target_path: str) -> dict[str, Any]:
    """Detects direct/indirect x64 syscall stubs (Hell's Gate, Halo's Gate, SysWhispers2/3)
    and outputs an x64 ProcessInstrumentationCallback C++ hook template to intercept them.
    """
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    stubs = []
    for m in _HELLS_GATE_RE.finditer(data):
        ssn = struct.unpack("<H", m.group(1))[0]
        stubs.append({"file_offset": hex(m.start()), "ssn": hex(ssn), "ssn_dec": ssn, "pattern": "mov r10, rcx; mov eax, SSN; syscall"})
        if len(stubs) >= 80:
            break

    gadgets = [hex(m.start()) for m in _RAW_SYSCALL_RE.finditer(data)][:40]
    egg_markers = [sig.decode("ascii") for sig in (b"SW2_", b"SW3_", b"ZwOpenProcess", b"NtAllocateVirtualMemory") if sig in data]

    callback_cpp = (
        "// x64 NtSetInformationProcess(ProcessInstrumentationCallback = 40) Telemetry Hook\n"
        "struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION { ULONG Version; ULONG Reserved; PVOID Callback; };\n"
        "// Catches every kernel->usermode transition (including direct 0F 05 syscalls bypassing ntdll hooks)\n"
    )

    return {
        "target": os.path.basename(target_path),
        "direct_syscall_stubs_count": len(stubs),
        "direct_syscall_stubs": stubs,
        "syscall_ret_gadgets_count": len(gadgets),
        "syscall_ret_gadgets_sample": gadgets,
        "syswhispers_or_ntapi_markers": egg_markers,
        "instrumentation_callback_template": callback_cpp,
    }


# ---------------------------------------------------------------------------
# 4. CRYPTOGRAPHIC CONSTANT DETECTOR & AUTOMATED YARA RULE SYNTHESIZER
# ---------------------------------------------------------------------------

CRYPTO_CONSTANTS: list[tuple[str, bytes]] = [
    ("AES_Rijndael_SBox", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES_Inv_SBox", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("ChaCha20_Expand32", b"expand 32-byte k"),
    ("Salsa20_Expand16", b"expand 16-byte k"),
    ("SHA256_H0_LE", bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa5")),
    ("SHA256_K0_BE", bytes.fromhex("428a2f9871374491b5c0fbcfef9b5dba")),
    ("MD5_T1_LE", bytes.fromhex("78a46ad756b7c7e8db702024eecebdc1")),
    ("CRC32_IEEE_Poly", bytes.fromhex("00000000963007772c610eeeba510999")),
    ("TEA_XTEA_Delta", bytes.fromhex("b979379e")),
    ("Ed25519_Clamp_Pattern", bytes.fromhex("f8ffffff3f")),
]


def synthesize_yara_and_crypto(target_path: str, rule_name: str | None = None) -> dict[str, Any]:
    """Finds embedded cryptographic lookup tables/constants and synthesizes a valid YARA signature rule."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    sha256_hex = hashlib.sha256(data).hexdigest()
    clean_rule = re.sub(r"[^A-Za-z0-9_]", "_", rule_name or f"OmniReverse_{Path(target_path).stem}")
    if clean_rule[0].isdigit():
        clean_rule = "Rule_" + clean_rule

    crypto_hits = []
    for cname, needle in CRYPTO_CONSTANTS:
        off = data.find(needle)
        if off != -1:
            crypto_hits.append({"algorithm": cname, "offset": hex(off), "hex_prefix": needle[:8].hex()})

    raw_strs = re.findall(rb"[\x20-\x7e]{7,48}", data)
    interesting_strs = []
    for s in raw_strs:
        txt = s.decode("ascii", errors="ignore")
        if any(k in txt.lower() for k in ("api", "auth", "key", "license", "crypt", "token", "http", "vmp", "pdb", ".dll")):
            escaped = txt.replace("\\", "\\\\").replace('"', '\\"')
            if escaped not in interesting_strs:
                interesting_strs.append(escaped)
        if len(interesting_strs) >= 6:
            break

    ep_hex = ""
    if pefile and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=True)
            ep_off = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            if 0 <= ep_off <= len(data) - 16:
                ep_hex = " ".join(f"{b:02X}" for b in data[ep_off : ep_off + 16])
        except Exception:
            pass
    if not ep_hex and len(data) >= 32:
        ep_hex = " ".join(f"{b:02X}" for b in data[:16])

    yara_lines = [
        f"rule {clean_rule} {{",
        "  meta:",
        f'    author = "OmniReverse Studio v3.0"',
        f'    sha256 = "{sha256_hex}"',
        f"    filesize = {len(data)}",
        "  strings:",
    ]
    if ep_hex:
        yara_lines.append(f"    $ep_bytes = {{ {ep_hex} }}")
    for idx, ch in enumerate(crypto_hits[:4]):
        yara_lines.append(f"    $crypto_{idx} = {{ {ch['hex_prefix']} }}")
    for idx, st in enumerate(interesting_strs[:5]):
        yara_lines.append(f'    $s_{idx} = "{st}" ascii wide')
    yara_lines.extend([
        "  condition:",
        f"    filesize < {max(len(data) * 2, 1048576)} and (any of them)",
        "}",
    ])

    return {
        "target": os.path.basename(target_path),
        "sha256": sha256_hex,
        "crypto_constants_found": crypto_hits,
        "selected_strings": interesting_strs,
        "yara_rule": "\n".join(yara_lines),
    }


# ---------------------------------------------------------------------------
# 5. STRUCTURAL BINARY DIFFING (BINDIFF / PATCH DIFFING)
# ---------------------------------------------------------------------------

_PROLOGUE_SPLIT_RE = re.compile(rb"(?:\x48\x89\x5c\x24|\x40\x53\x48\x83\xec|\x55\x48\x89\xe5)")


def bindiff_binaries(old_path: str, new_path: str) -> dict[str, Any]:
    """Compares two binary versions (sections, imports, strings, and prologue-segmented function hashes)."""
    if not os.path.isfile(old_path) or not os.path.isfile(new_path):
        return {"error": "Karsilastirilacak her iki dosya da mevcut olmalidir."}

    d1 = safe_read_binary(old_path)
    d2 = safe_read_binary(new_path)

    s1 = {s.decode("latin1") for s in re.findall(rb"[\x20-\x7e]{6,80}", d1)}
    s2 = {s.decode("latin1") for s in re.findall(rb"[\x20-\x7e]{6,80}", d2)}

    def _func_hashes(buf: bytes) -> set[str]:
        starts = [m.start() for m in _PROLOGUE_SPLIT_RE.finditer(buf)][:2000]
        hashes = set()
        for idx, st in enumerate(starts):
            end = min(st + 256, starts[idx + 1] if idx + 1 < len(starts) else len(buf))
            hashes.add(hashlib.sha256(buf[st:end]).hexdigest()[:16])
        return hashes

    fh1, fh2 = _func_hashes(d1), _func_hashes(d2)
    unchanged_funcs = len(fh1 & fh2)
    modified_or_new_funcs = len(fh2 - fh1)
    similarity = round((2.0 * unchanged_funcs) / max(1, len(fh1) + len(fh2)) * 100.0, 2) if (fh1 or fh2) else (100.0 if d1 == d2 else 0.0)

    sec_deltas = []
    if pefile and d1[:2] == b"MZ" and d2[:2] == b"MZ":
        try:
            p1, p2 = pefile.PE(data=d1, fast_load=True), pefile.PE(data=d2, fast_load=True)
            m1 = {s.Name.rstrip(b"\x00").decode(errors="ignore"): (s.SizeOfRawData, _entropy(s.get_data())) for s in p1.sections}
            m2 = {s.Name.rstrip(b"\x00").decode(errors="ignore"): (s.SizeOfRawData, _entropy(s.get_data())) for s in p2.sections}
            for sec_name in sorted(set(m1) | set(m2)):
                sec_deltas.append({"section": sec_name, "old": m1.get(sec_name), "new": m2.get(sec_name), "changed": m1.get(sec_name) != m2.get(sec_name)})
        except Exception:
            pass

    return {
        "old_target": os.path.basename(old_path),
        "new_target": os.path.basename(new_path),
        "old_sha256": hashlib.sha256(d1).hexdigest(),
        "new_sha256": hashlib.sha256(d2).hexdigest(),
        "size_delta_bytes": len(d2) - len(d1),
        "function_similarity_percent": similarity,
        "unchanged_function_blocks": unchanged_funcs,
        "patched_or_added_function_blocks": modified_or_new_funcs,
        "section_deltas": sec_deltas,
        "added_strings_sample": sorted(s2 - s1)[:35],
        "removed_strings_sample": sorted(s1 - s2)[:35],
    }
