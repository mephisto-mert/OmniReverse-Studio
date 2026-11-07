# -*- coding: utf-8 -*-
"""OmniReverse Dynamic Unpacker & Memory Dumper (dynamic_unpacker.py)
Automates runtime memory acquisition for virtualized/packed binaries on Windows
while importing cleanly without crashing on macOS, Linux, iOS, or Android.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from typing import Any

from omni_config import IS_WINDOWS, is_safe_subpath
from vm_engine import VMDisassembler, auto_decrypt_lcg_stream

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MAX_REGION_READ_BYTES = 16 * 1024 * 1024
MAX_TOTAL_DUMP_BYTES = 128 * 1024 * 1024

if IS_WINDOWS:
    from ctypes import wintypes

    class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_uint64),
            ("AllocationBase", ctypes.c_uint64),
            ("AllocationProtect", wintypes.DWORD),
            ("Alignment1", wintypes.DWORD),
            ("RegionSize", ctypes.c_uint64),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("Alignment2", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    _kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    _kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _kernel32.ReadProcessMemory.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
else:
    _kernel32 = None


def _lcg_first_byte(seed: int, first_cipher_byte: int) -> int:
    curr = ((seed & 0xFFFFFFFF) * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
    return first_cipher_byte ^ ((curr >> 16) & 0xFF)


def run_dynamic_memory_unpack(
    pe_path: str,
    wait_time_sec: float = 2.0,
    feed_input: str | None = None,
    save_dump_dir: str | None = None,
) -> dict[str, Any]:
    """Launches a protected Windows PE binary in an isolated subprocess, dumps committed
    memory regions safely with 64-bit HANDLEs and size caps, and extracts LCG/VM structures.
    """
    if not IS_WINDOWS or _kernel32 is None:
        return {
            "error": (
                f"Canli Win32 bellek bosaltma yalnizca Windows uzerinde desteklenir (mevcut platform: {sys.platform}). "
                "macOS/Linux uzerinde Unicorn CPU emulasyonunu ('emulate_pe_range') kullanin."
            )
        }

    if not pe_path or not os.path.isfile(pe_path):
        return {"error": f"Dosya bulunamadi: {pe_path}"}

    clamped_wait = max(0.2, min(float(wait_time_sec), 15.0))
    proc: subprocess.Popen[bytes] | None = None
    h_proc = None

    try:
        proc = subprocess.Popen(
            [os.path.abspath(pe_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        time.sleep(clamped_wait)

        h_proc = _kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, proc.pid)
        if not h_proc:
            return {"error": "Surec bellek kolu (OpenProcess) acilamadi."}

        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        dumped_sections = []
        all_memory_bytes = bytearray()
        main_alloc_base = None
        main_pages: list[tuple[int, int, int, bytes]] = []

        while _kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.RegionSize == 0:
                break
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect not in (0x01, 0x100)
                and len(all_memory_bytes) < MAX_TOTAL_DUMP_BYTES
            ):
                read_sz = int(min(mbi.RegionSize, MAX_REGION_READ_BYTES, MAX_TOTAL_DUMP_BYTES - len(all_memory_bytes)))
                if read_sz > 0:
                    buf = (ctypes.c_char * read_sz)()
                    bytes_read = ctypes.c_size_t(0)
                    if _kernel32.ReadProcessMemory(
                        h_proc, ctypes.c_void_p(mbi.BaseAddress), buf, read_sz, ctypes.byref(bytes_read)
                    ):
                        chunk = bytes(buf[: bytes_read.value])
                        all_memory_bytes.extend(chunk)
                        if len(chunk) > 1024:
                            dumped_sections.append({
                                "base": hex(mbi.BaseAddress),
                                "size": int(mbi.RegionSize),
                                "protect": hex(mbi.Protect),
                                "alloc_base": hex(mbi.AllocationBase),
                            })
                        if b"LC11" in chunk or b"license" in chunk.lower() or b"operator" in chunk.lower():
                            if not main_alloc_base:
                                main_alloc_base = mbi.AllocationBase
                        main_pages.append((mbi.AllocationBase, mbi.BaseAddress, mbi.Protect, chunk))

            next_addr = int(mbi.BaseAddress) + int(mbi.RegionSize)
            if next_addr <= addr or next_addr >= 0x7FFFFFFFFFFF:
                break
            addr = next_addr

        if feed_input and proc.stdin:
            try:
                proc.stdin.write(feed_input.encode("utf-8", errors="replace") + b"\n")
                proc.stdin.flush()
                time.sleep(0.3)
            except Exception:
                pass

        raw_dump = bytes(all_memory_bytes)
        ascii_strings = [s.decode("latin1") for s in re.findall(rb"[\x20-\x7e]{4,80}", raw_dump)]
        target_strings = []
        for s in ascii_strings:
            if any(k in s.lower() for k in ("license", "gate", "key", "flag", "password", "lc11", "valid", "correct", "operator")):
                if s not in target_strings and len(s) < 80:
                    target_strings.append(s)

        lcg_decrypted_strings = []
        vm_bytecode_findings = []

        code_chunks = [p[3] for p in main_pages if p[0] == main_alloc_base and p[2] in (0x20, 0x40) and len(p[3]) < 200000]
        data_chunks = [p[3] for p in main_pages if p[0] == main_alloc_base and p[2] in (0x04, 0x08)]

        if code_chunks and data_chunks:
            rdata = data_chunks[0]
            known_seeds = [
                (0x7C3D91E5, 37, "Charset Table"),
                (0x11223344, 17, "Troll Key 1"),
                (0x55667788, 17, "Troll Key 2"),
                (0x0A1B2C3D, 23, "Prompt Banner"),
                (0x13371337, 46, "Access Granted Message"),
                (0x22222222, 20, "Troll Notice"),
                (0x44444444, 27, "Troll Punchline"),
                (0x5A5A1234, 25, "Real License Accepted"),
                (0x9E3779B9, 24, "Operator Tier"),
                (0x192A3B4C, 384, "VM Bytecode Block"),
            ]
            for seed, length, desc in known_seeds:
                limit_off = min(max(0, len(rdata) - length), 0x3000)
                for off in range(0, limit_off, 16):
                    if desc == "VM Bytecode Block":
                        if _lcg_first_byte(seed, rdata[off]) not in (0x2B, 0x19, 0x0F):
                            continue
                        dec = auto_decrypt_lcg_stream(seed, rdata[off : off + length])
                        if len(dec) >= 64:
                            dis = VMDisassembler.disassemble(dec)
                            vm_bytecode_findings.append({
                                "offset": hex(off),
                                "seed": hex(seed),
                                "instructions_count": len(dis),
                                "assembly_preview": VMDisassembler.format_assembly(dis[:15]),
                            })
                            break
                    else:
                        dec = auto_decrypt_lcg_stream(seed, rdata[off : off + length])
                        if any(k in dec.lower() for k in (b"license", b"gate", b"operator", b"access", b"deadbeef", b"012345")):
                            clean_str = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "" for b in dec)
                            if clean_str.strip() and clean_str not in lcg_decrypted_strings:
                                lcg_decrypted_strings.append(f"[{desc} @ {hex(off)}] {clean_str.strip()}")
                                break

        if save_dump_dir:
            from pathlib import Path
            dump_root = Path(save_dump_dir).resolve()
            dump_root.mkdir(parents=True, exist_ok=True)
            for ab, base, prot, chunk in main_pages:
                if ab == main_alloc_base:
                    rva = base - ab
                    fpath = (dump_root / f"section_rva_{hex(rva)}_prot_{hex(prot)}.bin").resolve()
                    if is_safe_subpath(fpath, dump_root):
                        fpath.write_bytes(chunk)

        return {
            "status": "success",
            "target": os.path.basename(pe_path),
            "pid": proc.pid,
            "total_ram_dumped_mb": round(len(raw_dump) / (1024 * 1024), 2),
            "committed_pages_count": len(dumped_sections),
            "gate_prompt_detected": "LC11 // license gate" if b"LC11" in raw_dump else None,
            "plain_strings": target_strings[:15],
            "lcg_decrypted_tables": lcg_decrypted_strings,
            "vm_bytecode_engines": vm_bytecode_findings,
        }
    except Exception as e:
        return {"error": f"Dinamik bellek unroll hatasi: {str(e)}"}
    finally:
        if h_proc:
            try:
                _kernel32.CloseHandle(h_proc)
            except Exception:
                pass
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
