# -*- coding: utf-8 -*-
"""OmniReverse Visual CFG, Hex/Binary Patcher & Live Memory/Pointer Scanner (visual_patch_memory_engine.py)
Implements:
1. Interactive Hex + ASCII Inspector & Non-Destructive Binary Patcher (x86/x64 Jcc/NOP/RET presets & raw hex)
2. Control Flow Graph (CFG) & Call-Graph Builder with Inline Dark-Theme SVG Renderer
3. Cheat-Engine-Style Live Process Memory Value Scanner (First/Next Scan) & 64-bit Pointer Scanner
"""

from __future__ import annotations

import ctypes
import hashlib
import html
import os
import re
import struct
import sys
from pathlib import Path
from typing import Any

from omni_config import IS_WINDOWS, STUDIO_ROOT, is_safe_subpath, safe_read_binary

try:
    import capstone
except ImportError:
    capstone = None

try:
    import pefile
except ImportError:
    pefile = None


def _va_or_off_to_file_offset(data: bytes, offset_or_va: int) -> tuple[int, int]:
    if pefile and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=True)
            img_base = pe.OPTIONAL_HEADER.ImageBase
            if offset_or_va == 0:
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                return pe.get_offset_from_rva(ep), img_base + ep
            if offset_or_va >= img_base:
                return pe.get_offset_from_rva(offset_or_va - img_base), offset_or_va
        except Exception:
            pass
    return max(0, int(offset_or_va)), max(0, int(offset_or_va))


# ---------------------------------------------------------------------------
# 1. HEX VIEWER & NON-DESTRUCTIVE BINARY PATCHER
# ---------------------------------------------------------------------------

def _assemble_patch_preset(spec: str, current_bytes: bytes) -> bytes:
    s = spec.strip()
    low = s.lower()
    if low == "nop":
        return b"\x90"
    if low.startswith("nop:"):
        cnt = max(1, min(int(low.split(":", 1)[1]), 256))
        return b"\x90" * cnt
    if low in ("ret", "retn"):
        return b"\xc3"
    if low in ("ret_true", "mov eax, 1; ret", "mov eax,1;ret"):
        return b"\xb8\x01\x00\x00\x00\xc3"
    if low in ("ret_false", "xor eax, eax; ret", "xor eax,eax;ret"):
        return b"\x31\xc0\xc3"
    if low in ("force_jmp", "jcc_to_jmp"):
        if len(current_bytes) >= 2 and 0x70 <= current_bytes[0] <= 0x7F:
            return bytes([0xEB, current_bytes[1]])
        if len(current_bytes) >= 6 and current_bytes[0] == 0x0F and 0x80 <= current_bytes[1] <= 0x8F:
            return b"\xe9" + current_bytes[2:6] + b"\x90"
        raise ValueError("Secilen ofsette kisa (7x) veya yakin (0F 8x) kosullu sicrama bulunamadi.")
    clean_hex = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(clean_hex) >= 2 and len(clean_hex) % 2 == 0:
        return bytes.fromhex(clean_hex)
    raise ValueError(f"Gecersiz yama tanimi: {spec!r} ('nop:N', 'ret_true', 'ret_false', 'force_jmp' veya hex dizisi kullanin).")


def hex_view_and_patch(
    target_path: str,
    offset_or_va: int = 0,
    length: int = 128,
    patch_spec: str = "",
    output_path: str | None = None,
) -> dict[str, Any]:
    """Renders formatted Hex + ASCII dump at offset/VA, and optionally applies a safe non-destructive binary patch."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = bytearray(safe_read_binary(target_path))
    file_off, disp_va = _va_or_off_to_file_offset(bytes(data), offset_or_va)
    if file_off < 0 or file_off >= len(data):
        return {"error": f"Ofset dosya sinirlari disinda: {hex(file_off)}"}

    patch_info = None
    if patch_spec and patch_spec.strip():
        patch_bytes = _assemble_patch_preset(patch_spec, bytes(data[file_off : file_off + 16]))
        if file_off + len(patch_bytes) > len(data):
            return {"error": "Yama baytlari dosya sonunu asiyor."}

        orig_bytes = bytes(data[file_off : file_off + len(patch_bytes)])
        data[file_off : file_off + len(patch_bytes)] = patch_bytes

        src_p = Path(target_path).resolve()
        if output_path:
            out_p = Path(output_path).resolve()
            exports_root = (STUDIO_ROOT / ".exports").resolve()
            if out_p == src_p or (not is_safe_subpath(out_p, STUDIO_ROOT) and not is_safe_subpath(out_p, exports_root)):
                exports_root.mkdir(parents=True, exist_ok=True)
                out_p = exports_root / f"{src_p.stem}_patched{src_p.suffix}"
        else:
            out_p = src_p.with_name(f"{src_p.stem}_patched{src_p.suffix or '.bin'}")

        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(bytes(data))
        patch_info = {
            "patched_file": str(out_p),
            "file_offset": hex(file_off),
            "original_hex": orig_bytes.hex(),
            "patched_hex": patch_bytes.hex(),
            "new_sha256": hashlib.sha256(bytes(data)).hexdigest(),
        }

    win_len = max(16, min(int(length), 1024))
    slice_buf = bytes(data[file_off : min(len(data), file_off + win_len)])
    hex_lines = []
    for i in range(0, len(slice_buf), 16):
        row = slice_buf[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in row).ljust(47)
        asc_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        hex_lines.append(f"{disp_va + i:012X}  {hex_part}  |{asc_part}|")

    return {
        "target": os.path.basename(target_path),
        "file_offset": hex(file_off),
        "virtual_address": hex(disp_va),
        "hex_dump": "\n".join(hex_lines),
        "patch_result": patch_info,
    }


# ---------------------------------------------------------------------------
# 2. VISUAL CONTROL FLOW GRAPH (CFG) & CALL GRAPH BUILDER (JSON + SVG)
# ---------------------------------------------------------------------------

def build_visual_cfg(
    target_path: str,
    offset_or_va: int = 0,
    max_instructions: int = 90,
    arch: str = "x64",
) -> dict[str, Any]:
    """Partitions disassembled instructions into Basic Blocks, computes edges & calls, and emits dark-theme SVG."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}
    if not capstone:
        return {"error": "capstone modulu gerekli."}

    data = safe_read_binary(target_path)
    file_off, base_va = _va_or_off_to_file_offset(data, offset_or_va)
    if file_off >= len(data):
        return {"error": "Baslangic adresi dosya sinirlari disinda."}

    cs_mode = capstone.CS_MODE_64 if arch.lower() == "x64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
    md.detail = False

    insns = list(md.disasm(data[file_off : min(len(data), file_off + 2048)], base_va))[: max(8, min(int(max_instructions), 250))]
    if not insns:
        return {"error": "Belirtilen adreste gecerli makine komutu cozulemedi."}

    leaders = {insns[0].address}
    calls: list[dict[str, str]] = []
    for idx, ins in enumerate(insns):
        mn = ins.mnemonic.lower()
        op = ins.op_str.strip()
        if mn == "call":
            calls.append({"from": hex(ins.address), "target": op})
        elif mn.startswith("j"):
            if op.startswith("0x"):
                try:
                    leaders.add(int(op, 16))
                except ValueError:
                    pass
            if idx + 1 < len(insns):
                leaders.add(insns[idx + 1].address)
        elif mn.startswith("ret") and idx + 1 < len(insns):
            leaders.add(insns[idx + 1].address)

    blocks: list[dict[str, Any]] = []
    cur_lines: list[str] = []
    cur_start = insns[0].address
    cur_last = insns[0]

    for ins in insns:
        if ins.address in leaders and cur_lines:
            blocks.append({
                "id": f"bb_{cur_start:x}",
                "start_va": hex(cur_start),
                "end_va": hex(cur_last.address),
                "lines": cur_lines,
                "last_mnemonic": cur_last.mnemonic.lower(),
                "last_op": cur_last.op_str.strip(),
            })
            cur_lines = []
            cur_start = ins.address
        cur_lines.append(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}".strip())
        cur_last = ins
    if cur_lines:
        blocks.append({
            "id": f"bb_{cur_start:x}",
            "start_va": hex(cur_start),
            "end_va": hex(cur_last.address),
            "lines": cur_lines,
            "last_mnemonic": cur_last.mnemonic.lower(),
            "last_op": cur_last.op_str.strip(),
        })

    va_to_id = {b["start_va"].lower(): b["id"] for b in blocks}
    edges: list[dict[str, str]] = []
    for idx, blk in enumerate(blocks):
        mn = blk["last_mnemonic"]
        op = blk["last_op"].lower()
        if mn.startswith("j"):
            if op in va_to_id:
                edges.append({"from": blk["id"], "to": va_to_id[op], "kind": "unconditional" if mn == "jmp" else "branch_taken"})
            if mn != "jmp" and idx + 1 < len(blocks):
                edges.append({"from": blk["id"], "to": blocks[idx + 1]["id"], "kind": "fallthrough"})
        elif not mn.startswith("ret") and idx + 1 < len(blocks):
            edges.append({"from": blk["id"], "to": blocks[idx + 1]["id"], "kind": "fallthrough"})

    # Render clean vertical SVG layout
    vis_blocks = blocks[:14]
    y_cursor = 20
    svg_parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="660" viewBox="0 0 660 {H}" style="background:#0d1117;font-family:Consolas,monospace;font-size:12px">']
    for b in vis_blocks:
        shown = b["lines"][:8]
        box_h = 28 + len(shown) * 16
        svg_parts.append(f'<rect x="30" y="{y_cursor}" width="600" height="{box_h}" rx="6" fill="#161b22" stroke="#58a6ff" stroke-width="1.4"/>')
        svg_parts.append(f'<text x="44" y="{y_cursor + 18}" fill="#79c0ff" font-weight="bold">[{b["id"]}] {b["start_va"]}</text>')
        for l_i, line_txt in enumerate(shown):
            svg_parts.append(f'<text x="44" y="{y_cursor + 36 + l_i * 16}" fill="#e6edf3">{html.escape(line_txt[:74])}</text>')
        y_cursor += box_h + 26
        svg_parts.append(f'<line x1="330" y1="{y_cursor - 26}" x2="330" y2="{y_cursor - 4}" stroke="#3fb950" stroke-width="1.5"/>')

    total_h = max(120, y_cursor + 10)
    svg_str = "\n".join(svg_parts).replace("{H}", str(total_h)) + "\n</svg>"

    return {
        "target": os.path.basename(target_path),
        "entry_va": hex(base_va),
        "basic_blocks_count": len(blocks),
        "edges_count": len(edges),
        "calls_count": len(calls),
        "basic_blocks": blocks[:30],
        "edges": edges[:50],
        "call_targets": calls[:30],
        "svg": svg_str,
    }


# ---------------------------------------------------------------------------
# 3. LIVE PROCESS MEMORY & POINTER SCANNER (Cheat-Engine Style, Win32 x64)
# ---------------------------------------------------------------------------

def _encode_scan_needle(scan_type: str, value: str) -> bytes:
    st = (scan_type or "ascii").lower().strip()
    if st == "int32":
        return struct.pack("<i", int(value, 0))
    if st == "uint32":
        return struct.pack("<I", int(value, 0))
    if st == "int64":
        return struct.pack("<q", int(value, 0))
    if st in ("uint64", "ptr"):
        return struct.pack("<Q", int(value, 0))
    if st == "float":
        return struct.pack("<f", float(value))
    if st == "double":
        return struct.pack("<d", float(value))
    if st == "utf16":
        return value.encode("utf-16le")
    if st == "hex":
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", value))
    return value.encode("utf-8")


def live_memory_scanner(
    pid: int,
    scan_type: str = "ascii",
    value: str = "",
    previous_addresses: list[str] | None = None,
    pointer_target_va: int | None = None,
    max_offset: int = 0x400,
    max_hits: int = 150,
) -> dict[str, Any]:
    """Scans committed readable RAM of a live Win32 x64 process for values (First/Next Scan) or 64-bit pointer chains."""
    if not IS_WINDOWS:
        return {"error": f"Canli Win32 bellek tarayici yalnizca Windows uzerinde calisir (mevcut: {sys.platform})."}

    from dynamic_unpacker import MEMORY_BASIC_INFORMATION64, MEM_COMMIT, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, _kernel32

    if _kernel32 is None or int(pid) <= 0:
        return {"error": f"Gecersiz PID: {pid}"}

    is_ptr_scan = pointer_target_va is not None and int(pointer_target_va) > 0
    if not is_ptr_scan and not value:
        return {"error": "Aranacak 'value' veya 'pointer_target_va' belirtilmelidir."}

    needle = b"" if is_ptr_scan else _encode_scan_needle(scan_type, value)
    h_proc = _kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, int(pid))
    if not h_proc:
        return {"error": f"PID {pid} acilamadi (Erisim engellendi veya surec mevcut degil)."}

    hits: list[dict[str, Any]] = []
    regions_scanned = 0
    try:
        # Next-Scan mode: re-verify only previously matched addresses!
        if previous_addresses and not is_ptr_scan:
            n_len = len(needle)
            buf = (ctypes.c_char * n_len)()
            rd = ctypes.c_size_t(0)
            for raw_addr in previous_addresses[:2000]:
                va = int(str(raw_addr), 16) if str(raw_addr).lower().startswith("0x") else int(raw_addr)
                if _kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(va), buf, n_len, ctypes.byref(rd)):
                    if bytes(buf[: rd.value]) == needle:
                        hits.append({"address": hex(va), "matched_hex": needle.hex()})
            return {"mode": "next_scan", "pid": int(pid), "remaining_matches": len(hits), "matches": hits[:max_hits]}

        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        lo_ptr = (int(pointer_target_va) - abs(int(max_offset))) if is_ptr_scan else 0
        hi_ptr = int(pointer_target_va) if is_ptr_scan else 0

        while _kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.RegionSize == 0:
                break
            if mbi.State == MEM_COMMIT and mbi.Protect not in (0x01, 0x100) and mbi.RegionSize <= 33_554_432:
                read_sz = int(min(mbi.RegionSize, 8_388_608))
                buf = (ctypes.c_char * read_sz)()
                rd = ctypes.c_size_t(0)
                if _kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(mbi.BaseAddress), buf, read_sz, ctypes.byref(rd)):
                    chunk = bytes(buf[: rd.value])
                    regions_scanned += 1
                    if is_ptr_scan:
                        for off in range(0, len(chunk) - 8, 8):
                            qval = struct.unpack_from("<Q", chunk, off)[0]
                            if lo_ptr <= qval <= hi_ptr:
                                delta = int(pointer_target_va) - qval
                                hits.append({
                                    "pointer_holder_va": hex(int(mbi.BaseAddress) + off),
                                    "points_to": hex(qval),
                                    "struct_offset": hex(delta),
                                })
                                if len(hits) >= max_hits:
                                    break
                    else:
                        pos = 0
                        while len(hits) < max_hits:
                            idx = chunk.find(needle, pos)
                            if idx == -1:
                                break
                            hits.append({"address": hex(int(mbi.BaseAddress) + idx), "protect": hex(mbi.Protect)})
                            pos = idx + max(1, len(needle))
            if len(hits) >= max_hits:
                break
            nxt = int(mbi.BaseAddress) + int(mbi.RegionSize)
            if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
                break
            addr = nxt
    finally:
        _kernel32.CloseHandle(h_proc)

    return {
        "mode": "pointer_scan" if is_ptr_scan else "first_scan",
        "pid": int(pid),
        "scan_type": scan_type,
        "regions_scanned": regions_scanned,
        "matches_count": len(hits),
        "matches": hits[:max_hits],
    }
