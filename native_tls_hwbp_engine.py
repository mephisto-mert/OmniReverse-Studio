# -*- coding: utf-8 -*-
"""
OmniReverse Native TLS Plaintext, HWBP/VEH & PE LEA Cross-Reference Engine
(native_tls_hwbp_engine.py)

Provides:
1. RIP-Relative LEA Cross-Reference & Conditional Branch (CALL+TEST+Jcc) Scanner for x64 PEs
2. Static Prologue & Curve Constant Scanner (libsodium Ed25519, TweetNaCl, SChannel, OpenSSL, VMProtect)
3. Standalone Zero-Timebomb C++ Native TLS Plaintext Dumper & HWBP/VEH Tracer SDK Generator
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, is_safe_subpath, safe_read_binary, sanitize_relative_filename

try:
    import pefile
except ImportError:
    pefile = None

_LEA_RIP_RE = re.compile(rb"\x48\x8d([\x0d\x15])(....)", re.DOTALL)

LIBSODIUM_ED25519_PROLOGUE = bytes([
    0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00
])
LIBSODIUM_WRAPPER_HEAD = bytes([
    0x48, 0x83, 0xEC, 0x38,
    0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
    0xE8
])
LIBSODIUM_WRAPPER_TAIL = bytes([0x48, 0x83, 0xC4, 0x38, 0xC3])

SIGFUNC_PROLOGUE = bytes([
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x81, 0xEC, 0x20, 0x01, 0x00, 0x00
])
SIGFUNC_POST_COOKIE = bytes([
    0x48, 0x33, 0xC4,
    0x48, 0x89, 0x84, 0x24, 0x10, 0x01, 0x00, 0x00,
    0x4D, 0x8B, 0xF0, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1
])

DEFAULT_AUDIT_STRINGS = [
    "Signature verification failed (invalid signature)",
    "Signature verification failed.",
    "Signature verification failed (invalid public key)",
    "Signature verification failed (invalid signature format)",
    "Signature verification failed (sig length)",
    "x-signature-ed25519",
    "x-signature-timestamp",
    "\"success\":false",
    "\"nonce\"",
    "Invalid license",
    "License expired",
    "Unauthorized",
    "Invalid key",
    "Invalid serial",
    "Activation failed",
    "HWID mismatch",
    "Trial expired",
    "Verification failed",
]


def _enum_pe_sections(
    target_path: str,
    raw_data: bytes | None = None,
) -> tuple[int, list[dict[str, Any]], bytes]:
    raw = raw_data if raw_data is not None else safe_read_binary(target_path)
    if not pefile or len(raw) < 64 or raw[:2] != b"MZ":
        return 0, [], raw
    pe = None
    try:
        pe = pefile.PE(data=raw, fast_load=True)
        img_base = pe.OPTIONAL_HEADER.ImageBase
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode("latin1", errors="ignore").strip("\x00")
            rva = sec.VirtualAddress
            vsize = sec.Misc_VirtualSize
            raw_off = sec.PointerToRawData
            raw_sz = sec.SizeOfRawData
            chars = sec.Characteristics
            is_exec = bool(chars & 0x20000000)
            sec_bytes = raw[raw_off : raw_off + min(raw_sz, vsize if vsize else raw_sz)]
            sections.append({
                "name": name,
                "rva": rva,
                "vsize": vsize,
                "raw_off": raw_off,
                "raw_sz": raw_sz,
                "is_exec": is_exec,
                "data": sec_bytes,
            })
        return img_base, sections, raw
    except Exception:
        return 0, [], raw
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def scan_pe_lea_xrefs(
    target_path: str,
    query_str: str | None = None,
    preloaded: tuple[int, list[dict[str, Any]], bytes] | None = None,
) -> dict[str, Any]:
    """Scans PE sections for target strings, locates x64 RIP-relative LEA refs in O(N) C-regex time, and inspects preceding CALL+TEST+Jcc branches."""
    if preloaded is None and (not target_path or not os.path.isfile(target_path)):
        return {"error": f"File not found: {target_path}"}

    try:
        img_base, sections, _ = preloaded if preloaded is not None else _enum_pe_sections(target_path)
    except Exception as exc:
        return {"error": str(exc)}
    if not sections:
        return {"error": "Target is not a valid PE binary or pefile is unavailable."}

    # Pre-index all RIP-relative LEA instructions across executable sections once (O(N) C-level pass)
    lea_index: dict[int, list[tuple[dict[str, Any], int, int]]] = {}
    for exec_sec in sections:
        if not exec_sec["is_exec"]:
            continue
        edata = exec_sec["data"]
        sec_rva = exec_sec["rva"]
        for m in _LEA_RIP_RE.finditer(edata):
            i = m.start()
            modrm = m.group(1)[0]
            disp = struct.unpack("<i", m.group(2))[0]
            target_rva = sec_rva + i + 7 + disp
            lea_index.setdefault(target_rva, []).append((exec_sec, i, modrm))

    targets = [query_str] if query_str else DEFAULT_AUDIT_STRINGS
    string_hits = []

    for s_text in targets:
        if not s_text:
            continue
        needle = s_text.encode("utf-8")
        for sec in sections:
            data = sec["data"]
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx == -1:
                    break
                str_rva = sec["rva"] + idx
                lea_refs = []
                for exec_sec, i, modrm in lea_index.get(str_rva, ()):
                    instr_rva = exec_sec["rva"] + i
                    branch_info = _inspect_branches_before_lea(exec_sec["data"], i, exec_sec["rva"], img_base)
                    lea_refs.append({
                        "section": exec_sec["name"],
                        "lea_rva": f"0x{instr_rva:X}",
                        "lea_va": f"0x{img_base + instr_rva:X}",
                        "register": "RCX" if modrm == 0x0D else "RDX",
                        "preceding_branches": branch_info,
                    })
                string_hits.append({
                    "string": s_text,
                    "section": sec["name"],
                    "string_rva": f"0x{str_rva:X}",
                    "string_va": f"0x{img_base + str_rva:X}",
                    "lea_xref_count": len(lea_refs),
                    "lea_xrefs": lea_refs,
                })
                start = idx + 1

    return {
        "target": os.path.basename(target_path),
        "image_base": f"0x{img_base:X}",
        "matches_count": len(string_hits),
        "matches": string_hits,
    }


def _inspect_branches_before_lea(edata: bytes, lea_off: int, sec_rva: int, img_base: int) -> list[dict[str, Any]]:
    """Scans up to 64 bytes before a LEA instruction for CALL rel32 + TEST EAX,EAX + JE/JNE patterns."""
    start = max(0, lea_off - 64)
    branches = []
    for pos in range(start, lea_off):
        # TEST EAX, EAX (85 C0) + JE rel8 (74 xx)
        if pos + 4 <= lea_off and edata[pos] == 0x85 and edata[pos + 1] == 0xC0 and edata[pos + 2] == 0x74:
            disp8 = struct.unpack_from("<b", edata, pos + 3)[0]
            jmp_target_off = pos + 4 + disp8
            call_rva = None
            if pos >= 5 and edata[pos - 5] == 0xE8:
                rel32 = struct.unpack_from("<i", edata, pos - 4)[0]
                call_rva = f"0x{sec_rva + pos + rel32:X}"
            branches.append({
                "pattern": "TEST EAX, EAX ; JE rel8 (85 C0 74)",
                "branch_rva": f"0x{sec_rva + pos + 2:X}",
                "branch_va": f"0x{img_base + sec_rva + pos + 2:X}",
                "jump_target_rva": f"0x{sec_rva + jmp_target_off:X}",
                "called_func_rva": call_rva,
            })
        # TEST EAX, EAX (85 C0) + JE rel32 (0F 84 xx xx xx xx)
        elif pos + 8 <= lea_off and edata[pos] == 0x85 and edata[pos + 1] == 0xC0 and edata[pos + 2] == 0x0F and edata[pos + 3] == 0x84:
            disp32 = struct.unpack_from("<i", edata, pos + 4)[0]
            jmp_target_off = pos + 8 + disp32
            call_rva = None
            if pos >= 5 and edata[pos - 5] == 0xE8:
                rel32 = struct.unpack_from("<i", edata, pos - 4)[0]
                call_rva = f"0x{sec_rva + pos + rel32:X}"
            branches.append({
                "pattern": "TEST EAX, EAX ; JE rel32 (85 C0 0F 84)",
                "branch_rva": f"0x{sec_rva + pos + 2:X}",
                "branch_va": f"0x{img_base + sec_rva + pos + 2:X}",
                "jump_target_rva": f"0x{sec_rva + jmp_target_off:X}",
                "called_func_rva": call_rva,
            })
        # JNE rel32 (0F 85 xx xx xx xx) landing near LEA
        elif pos + 6 <= lea_off and edata[pos] == 0x0F and edata[pos + 1] == 0x85:
            disp32 = struct.unpack_from("<i", edata, pos + 2)[0]
            jmp_target_off = pos + 6 + disp32
            if abs(jmp_target_off - lea_off) <= 16:
                branches.append({
                    "pattern": "JNE rel32 (0F 85 -> 6x NOP candidate)",
                    "branch_rva": f"0x{sec_rva + pos:X}",
                    "branch_va": f"0x{img_base + sec_rva + pos:X}",
                    "jump_target_rva": f"0x{sec_rva + jmp_target_off:X}",
                })
        # JNE rel8 (75 xx) landing near LEA
        elif pos + 2 <= lea_off and edata[pos] == 0x75:
            disp8 = struct.unpack_from("<b", edata, pos + 1)[0]
            jmp_target_off = pos + 2 + disp8
            if abs(jmp_target_off - lea_off) <= 16:
                branches.append({
                    "pattern": "JNE rel8 (75 -> 2x NOP candidate)",
                    "branch_rva": f"0x{sec_rva + pos:X}",
                    "branch_va": f"0x{img_base + sec_rva + pos:X}",
                    "jump_target_rva": f"0x{sec_rva + jmp_target_off:X}",
                })
    return branches


def scan_verify_detached_4stage(
    target_path: str,
    preloaded: tuple[int, list[dict[str, Any]], bytes] | None = None,
) -> dict[str, Any]:
    """
    Implements the exact 4-Stage Hierarchical Signature Verification Function Locator from dllmain.cpp (HookVerifyDetached):
      - Priority 0: Direct 14-byte libsodium crypto_sign_ed25519_verify_detached prologue in executable sections
      - Priority 1: 13-byte wrapper head + E8 rel32 + 5-byte tail, verifying whether call target begins with libsodium prologue
      - Priority 2: From each 'Signature verification failed' LEA ref, scans 512 bytes backward for E8 rel32 + 85 C0 (CALL + TEST EAX,EAX)
                    and validates if target is in executable section (promotes to Priority 1 if target has libsodium prologue)
      - Priority 3: SigVerifyFunc 19-byte prologue + 7-byte stack cookie skip + 20-byte post-cookie pattern (DR1 HWBP 0xA58F target)
    """
    if preloaded is None and (not target_path or not os.path.isfile(target_path)):
        return {"error": f"File not found: {target_path}"}
    try:
        img_base, sections, _ = preloaded if preloaded is not None else _enum_pe_sections(target_path)
    except Exception as exc:
        return {"error": str(exc)}
    if not sections:
        return {"is_pe": False, "priorities": {}}

    exec_ranges = [(s["rva"], s["rva"] + max(s["vsize"], len(s["data"])), s["name"], s["data"]) for s in sections if s["is_exec"]]

    def _in_exec(rva: int) -> tuple[bool, bytes]:
        for s_start, s_end, _, s_data in exec_ranges:
            if s_start <= rva < s_end:
                off = rva - s_start
                return True, s_data[off : off + 32]
        return False, b""

    p0_hits, p1_hits, p2_hits, p3_hits = [], [], [], []

    for s_start, _, s_name, edata in exec_ranges:
        # Priority 0: Direct libsodium prologue
        idx = 0
        while True:
            p = edata.find(LIBSODIUM_ED25519_PROLOGUE, idx)
            if p == -1:
                break
            rva = s_start + p
            p0_hits.append({"section": s_name, "rva": f"0x{rva:X}", "va": f"0x{img_base + rva:X}", "priority": 0})
            idx = p + 1

        # Priority 1: Wrapper kHead + E8 rel32 + kTail (C-speed bytes.find)
        w_total = len(LIBSODIUM_WRAPPER_HEAD) + 4 + len(LIBSODIUM_WRAPPER_TAIL)
        j = 0
        while True:
            j = edata.find(LIBSODIUM_WRAPPER_HEAD, j)
            if j == -1 or j + w_total > len(edata):
                break
            tail_off = j + len(LIBSODIUM_WRAPPER_HEAD) + 4
            if edata[tail_off : tail_off + len(LIBSODIUM_WRAPPER_TAIL)] == LIBSODIUM_WRAPPER_TAIL:
                rel = struct.unpack_from("<i", edata, j + len(LIBSODIUM_WRAPPER_HEAD))[0]
                wrap_rva = s_start + j
                target_rva = s_start + tail_off + rel
                ok_exec, target_head = _in_exec(target_rva)
                has_sodium = target_head.startswith(LIBSODIUM_ED25519_PROLOGUE)
                p1_hits.append({
                    "section": s_name,
                    "wrapper_rva": f"0x{wrap_rva:X}",
                    "call_target_rva": f"0x{target_rva:X}",
                    "call_target_va": f"0x{img_base + target_rva:X}",
                    "in_exec_section": ok_exec,
                    "verified_libsodium_prologue": has_sodium,
                    "priority": 1,
                })
            j += 1

        # Priority 3: SigVerifyFunc (DR1 HWBP target returning 0xA58F)
        s_total = len(SIGFUNC_PROLOGUE) + 7 + len(SIGFUNC_POST_COOKIE)
        j = 0
        while True:
            j = edata.find(SIGFUNC_PROLOGUE, j)
            if j == -1 or j + s_total > len(edata):
                break
            post_off = j + len(SIGFUNC_PROLOGUE) + 7
            if edata[post_off : post_off + len(SIGFUNC_POST_COOKIE)] == SIGFUNC_POST_COOKIE:
                rva = s_start + j
                p3_hits.append({
                    "section": s_name,
                    "rva": f"0x{rva:X}",
                    "va": f"0x{img_base + rva:X}",
                    "hwbp_register": "DR1",
                    "spoof_return_rax": "0xA58F",
                    "priority": 3,
                })
            j += 1

    # Priority 2: 512-byte backward scan from LEA to "Signature verification failed" for E8 rel32 + 85 C0
    sig_strings = [
        b"Signature verification failed (invalid signature)",
        b"Signature verification failed.",
        b"Signature verification failed",
    ]
    str_rvas = set()
    for sec in sections:
        sdata = sec["data"]
        for needle in sig_strings:
            idx = 0
            while True:
                p = sdata.find(needle, idx)
                if p == -1:
                    break
                str_rvas.add(sec["rva"] + p)
                idx = p + 1

    if str_rvas:
        for s_start, _, s_name, edata in exec_ranges:
            for m in _LEA_RIP_RE.finditer(edata):
                i = m.start()
                disp = struct.unpack("<i", m.group(2))[0]
                lea_rva = s_start + i
                if (lea_rva + 7 + disp) in str_rvas:
                    scan_start = max(0, i - 512)
                    for p in range(i - 7, scan_start - 1, -1):
                        if edata[p] == 0xE8 and edata[p + 5] == 0x85 and edata[p + 6] == 0xC0:
                            rel = struct.unpack_from("<i", edata, p + 1)[0]
                            call_rva = s_start + p
                            target_rva = call_rva + 5 + rel
                            ok_exec, target_head = _in_exec(target_rva)
                            if ok_exec:
                                has_sodium = target_head.startswith(LIBSODIUM_ED25519_PROLOGUE)
                                p2_hits.append({
                                    "section": s_name,
                                    "lea_rva": f"0x{lea_rva:X}",
                                    "call_instr_rva": f"0x{call_rva:X}",
                                    "target_func_rva": f"0x{target_rva:X}",
                                    "target_func_va": f"0x{img_base + target_rva:X}",
                                    "distance_before_lea": i - p,
                                    "promoted_to_priority_1": has_sodium,
                                    "priority": 1 if has_sodium else 2,
                                })
                                break

    return {
        "is_pe": True,
        "priority_0_direct_libsodium": p0_hits,
        "priority_1_wrapper_targets": p1_hits,
        "priority_2_backward_512b_call_test": p2_hits,
        "priority_3_sigverify_dr1_0xA58F": p3_hits,
    }


def audit_iat_and_integrity_surface(target_path: str, raw_data: bytes | None = None) -> dict[str, Any]:
    """
    Audits all 15 subsystems from KeyAuth_Patcher_1_3 in a target binary or C++ source:
      1. IAT Hook Surface (SChannel, OpenSSL, Winsock, BCrypt, Kernel32, NTDLL, UCRT, User32)
      2. Self-CRC / Disk-Memory Integrity Sync indicators (CreateFileW + CreateFileMappingW + MapViewOfFile + VirtualProtect)
      3. Anti-HWBP Debug Register Cloaking indicators (NtGetContextThread / NtSetContextThread / CONTEXT_DEBUG_REGISTERS)
      4. TLS Record Coalescing & SChannel SECBUFFER_EXTRA Multi-Buffer Reassembly indicators
      5. NTP Timebomb (UDP port 123 / 0xC0DEBABE XOR date encoding) & Adware (mshta.exe) indicators
      6. MSVC x64 std::string (MsvcString SSO/Heap) candidate literals
    """
    if raw_data is None and (not target_path or not os.path.isfile(target_path)):
        return {"error": f"File not found: {target_path}"}
    try:
        raw = raw_data if raw_data is not None else safe_read_binary(target_path)
    except Exception as exc:
        return {"error": str(exc)}

    # Check for 0xC0DEBABE XOR timebomb signature (BE BA DE C0 in little-endian or ascii)
    has_xor_timebomb = (b"\xbe\xba\xde\xc0" in raw) or (b"0xC0DEBABE" in raw)
    ntp_servers = [s.decode() for s in (b"pool.ntp.org", b"time.cloudflare.com", b"time.windows.com", b"time.google.com") if s in raw]
    has_mshta_adware = (b"mshta.exe" in raw) or (b"vbscript:Execute" in raw) or (b"Kariexscontxct" in raw) or (b"ShowStartupMessage" in raw)

    self_crc_apis = [s.decode() for s in (b"CreateFileW", b"CreateFileMappingW", b"MapViewOfFile", b"UnmapViewOfFile", b"QueryFullProcessImageNameW", b"VirtualProtect") if s in raw]
    anti_hwbp_apis = [s.decode() for s in (b"NtGetContextThread", b"NtSetContextThread", b"AddVectoredExceptionHandler", b"SetThreadContext", b"GetThreadContext") if s in raw]
    anti_exit_apis = [s.decode() for s in (b"exit", b"_exit", b"abort", b"terminate", b"MessageBoxA", b"MessageBoxW", b"puts", b"_write") if s in raw]
    tls_coalesce_apis = [s.decode() for s in (b"DecryptMessage", b"InitializeSecurityContext", b"SSL_read", b"SSL_read_ex", b"WSARecv", b"ioctlsocket", b"select") if s in raw]
    crypto_verify_apis = [s.decode() for s in (b"BCryptVerifySignature", b"EVP_DigestVerifyFinal", b"EVP_DigestVerify", b"EVP_PKEY_verify", b"ED25519_verify", b"crypto_sign_ed25519_verify_detached") if s in raw]

    # Scan for 64-char hex Ed25519 keys or known KeyAuth fake public key (binary, hex string, or C array initializer)
    has_fake_pk = (
        (b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" in raw)
        or (bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") in raw)
        or (b"0x9d,0x61,0xb1,0x9d" in raw.replace(b" ", b""))
    )

    iat_slots = enumerate_pe_iat_slots(target_path, raw_data=raw) if raw[:2] == b"MZ" else []
    msvc_strings = scan_msvc_string_structures(raw)

    return {
        "iat_hookable_slots_count": len(iat_slots),
        "iat_hookable_slots": iat_slots[:40],
        "msvc_std_string_sso_candidates": msvc_strings[:20],
        "self_crc_integrity_surface": {
            "detected_apis": self_crc_apis,
            "requires_mapviewoffile_writecopy_sync": len(self_crc_apis) >= 3,
        },
        "anti_hwbp_stealth_surface": {
            "detected_apis": anti_hwbp_apis,
            "requires_ntgetcontextthread_dr_cloak": any(x in anti_hwbp_apis for x in ("NtGetContextThread", "GetThreadContext")),
        },
        "tls_and_coalescing_surface": {
            "detected_apis": tls_coalesce_apis,
            "supports_tls_record_coalescing": "ioctlsocket" in tls_coalesce_apis or "WSARecv" in tls_coalesce_apis,
            "supports_schannel_secbuffer_extra": "DecryptMessage" in tls_coalesce_apis,
        },
        "crypto_verification_surface": {
            "detected_apis": crypto_verify_apis,
            "embedded_ed25519_fake_pk_detected": has_fake_pk,
        },
        "anti_exit_and_console_guard_surface": {
            "detected_apis": anti_exit_apis,
        },
        "timebomb_and_adware_audit": {
            "xor_0xC0DEBABE_timebomb_detected": has_xor_timebomb,
            "ntp_servers_detected": ntp_servers,
            "mshta_adware_popup_detected": has_mshta_adware,
        },
    }


def enumerate_pe_iat_slots(target_path: str, raw_data: bytes | None = None) -> list[dict[str, Any]]:
    """Walks IMAGE_DIRECTORY_ENTRY_IMPORT (OriginalFirstThunk / FirstThunk) and returns exact IAT slot RVAs/VAs."""
    if not pefile:
        return []
    if raw_data is None and (not target_path or not os.path.isfile(target_path)):
        return []
    pe = None
    try:
        raw = raw_data if raw_data is not None else safe_read_binary(target_path)
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        img_base = pe.OPTIONAL_HEADER.ImageBase
        watched = {
            "CreateFileW", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
            "QueryFullProcessImageNameW", "VirtualProtect", "recv", "WSARecv", "connect",
            "send", "WSASend", "DecryptMessage", "InitializeSecurityContextW", "InitializeSecurityContextA",
            "WinHttpReadData", "WinHttpQueryHeaders", "InternetReadFile", "HttpQueryInfoW", "HttpQueryInfoA",
            "SSL_read", "SSL_read_ex", "BCryptVerifySignature", "BCryptDecrypt", "NCryptVerifySignature",
            "CryptVerifySignatureW", "CertVerifyCertificateChainPolicy", "WinVerifyTrust",
            "exit", "_exit", "abort", "terminate", "puts", "_write", "MessageBoxA", "MessageBoxW",
            "CreateThread", "WaitForSingleObject", "Sleep", "GetProcAddress", "RegQueryValueExW",
            "NtGetContextThread", "NtSetContextThread",
        }
        slots = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("latin1", errors="ignore") if entry.dll else "unknown.dll"
                for imp in entry.imports:
                    fn_name = imp.name.decode("latin1", errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    if fn_name in watched or any(k in dll_name.lower() for k in ("secur32", "sspicli", "bcrypt", "ncrypt", "crypt32", "ws2_32", "winhttp", "wininet", "ssl", "crypto")):
                        iat_va = imp.address
                        iat_rva = iat_va - img_base if iat_va >= img_base else iat_va
                        slots.append({
                            "dll": dll_name,
                            "function": fn_name,
                            "iat_slot_rva": f"0x{iat_rva:X}",
                            "iat_slot_va": f"0x{iat_va:X}",
                        })
        return slots
    except Exception:
        return []
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def scan_msvc_string_structures(raw: bytes) -> list[dict[str, Any]]:
    """
    Fast C-speed jump scan for 32-byte x64 MSVC std::string (MsvcString) SSO instances:
      struct MsvcString { union { char* ptr; char sso[16]; }; size_t size; size_t cap; };
      For SSO strings: 4 <= size <= 15, cap == 15 (0x0f00000000000000 at +24), sso[size] == 0.
    """
    hits = []
    cap_needle = b"\x0f\x00\x00\x00\x00\x00\x00\x00"
    idx = 24
    while len(hits) < 25:
        pos = raw.find(cap_needle, idx)
        if pos == -1:
            break
        off = pos - 24
        if off >= 0 and off % 8 == 0:
            sz = struct.unpack_from("<Q", raw, off + 16)[0]
            if 4 <= sz <= 15 and raw[off + sz] == 0:
                s_bytes = raw[off : off + sz]
                if all(32 <= b <= 126 for b in s_bytes):
                    hits.append({
                        "offset": f"0x{off:X}",
                        "layout": "MsvcString_SSO (cap=15)",
                        "size": sz,
                        "value": s_bytes.decode("ascii", errors="ignore"),
                    })
        idx = pos + 1
    return hits


# ============================================================================
# Pure Python RFC 8032 Ed25519 + SHA-512 Engine (Port of patcher/ed25519_sign.h)
# ============================================================================
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_add(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_scalarmult(P: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    Q = (0, 1, 1, 0)
    cur = P
    while e > 0:
        if e & 1:
            Q = _ed_add(Q, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return Q


def _ed_encodepoint(P: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = P
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    out = bytearray(yp.to_bytes(32, "little"))
    out[31] |= (xp & 1) << 7
    return bytes(out)


def _ed_decodepoint(s: bytes) -> tuple[int, int, int, int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    x = _ed_xrecover(y)
    if (x & 1) != sign:
        x = _ED_P - x
    return (x, y, 1, (x * y) % _ED_P)


def ed25519_sign_detached_py(msg: bytes, sk64: bytes) -> bytes:
    """RFC 8032 / TweetNaCl Ed25519 detached signature generator (exact Python counterpart to ed25519_sign.h)."""
    import hashlib
    az = bytearray(hashlib.sha512(sk64[:32]).digest())
    az[0] &= 248
    az[31] &= 63
    az[31] |= 64
    a = int.from_bytes(az[:32], "little")
    pub = sk64[32:64]
    r_hash = hashlib.sha512(bytes(az[32:64]) + msg).digest()
    r = int.from_bytes(r_hash, "little") % _ED_L
    R = _ed_encodepoint(_ed_scalarmult(_ED_B, r))
    k_hash = hashlib.sha512(R + pub + msg).digest()
    k = int.from_bytes(k_hash, "little") % _ED_L
    S = ((r + k * a) % _ED_L).to_bytes(32, "little")
    return R + S


def ed25519_verify_detached_py(sig64: bytes, msg: bytes, pk32: bytes) -> bool:
    """RFC 8032 Ed25519 detached signature verifier."""
    import hashlib
    if len(sig64) != 64 or len(pk32) != 32:
        return False
    R_bytes = sig64[:32]
    S = int.from_bytes(sig64[32:64], "little")
    if S >= _ED_L:
        return False
    A = _ed_decodepoint(pk32)
    R = _ed_decodepoint(R_bytes)
    k = int.from_bytes(hashlib.sha512(R_bytes + pk32 + msg).digest(), "little") % _ED_L
    lhs = _ed_encodepoint(_ed_scalarmult(_ED_B, S))
    rhs = _ed_encodepoint(_ed_add(R, _ed_scalarmult(A, k)))
    return lhs == rhs


def ed25519_rfc8032_self_test(timestamp_str: str = "1773000000", body_str: str = '{"success":true,"message":"Logged in!"}') -> dict[str, Any]:
    """Tests RFC 8032 Ed25519 signing & verification using the corrected RFC 8032 Test Vector 1 keypair (fixing the 0x3d,0x55 -> 0x7f,0x60 seed bug in original dllmain.cpp)."""
    fake_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    fake_sk = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    msg = (timestamp_str + body_str).encode("utf-8")
    sig = ed25519_sign_detached_py(msg, fake_sk)
    verified = ed25519_verify_detached_py(sig, msg, fake_pk)
    return {
        "engine": "RFC 8032 Ed25519 + SHA-512 (ed25519_sign.h Parity)",
        "public_key_hex": fake_pk.hex(),
        "message_signed": timestamp_str + body_str,
        "x_signature_ed25519": sig.hex(),
        "signature_verified": verified,
        "original_dllmain_seed_bug_fixed": "Fixed bytes[30..31] from 0x3d,0x55 to RFC 8032 0x7f,0x60 so FAKE_SK mathematically matches FAKE_PK",
    }


def scan_native_crypto_prologues(
    target_path: str,
    preloaded: tuple[int, list[dict[str, Any]], bytes] | None = None,
) -> dict[str, Any]:
    """Scans PE executable sections or C++ source files for libsodium Ed25519 prologues, VMProtect sections, SChannel/OpenSSL hooks, and TweetNaCl constants."""
    if preloaded is None and (not target_path or not os.path.isfile(target_path)):
        return {"error": f"File not found: {target_path}"}

    try:
        img_base, sections, raw = preloaded if preloaded is not None else _enum_pe_sections(target_path)
    except Exception as exc:
        return {"error": str(exc)}
    is_pe = len(sections) > 0
    vmp_sections = [s["name"] for s in sections if s["name"].lower().startswith(".vmp")]
    sodium_hits = []
    wrapper_hits = []
    sigfunc_hits = []

    if is_pe:
        for sec in sections:
            if not sec["is_exec"]:
                continue
            edata = sec["data"]
            # 1. Direct libsodium ed25519_verify_detached prologue
            idx = 0
            while True:
                p = edata.find(LIBSODIUM_ED25519_PROLOGUE, idx)
                if p == -1:
                    break
                rva = sec["rva"] + p
                sodium_hits.append({"section": sec["name"], "rva": f"0x{rva:X}", "va": f"0x{img_base + rva:X}"})
                idx = p + 1

            # 2. Wrapper pattern (C-speed bytes.find)
            w_total = len(LIBSODIUM_WRAPPER_HEAD) + 4 + len(LIBSODIUM_WRAPPER_TAIL)
            j = 0
            while True:
                j = edata.find(LIBSODIUM_WRAPPER_HEAD, j)
                if j == -1 or j + w_total > len(edata):
                    break
                tail_start = j + len(LIBSODIUM_WRAPPER_HEAD) + 4
                if edata[tail_start : tail_start + len(LIBSODIUM_WRAPPER_TAIL)] == LIBSODIUM_WRAPPER_TAIL:
                    rel = struct.unpack_from("<i", edata, j + len(LIBSODIUM_WRAPPER_HEAD))[0]
                    rva = sec["rva"] + j
                    target_rva = sec["rva"] + tail_start + rel
                    wrapper_hits.append({
                        "section": sec["name"],
                        "wrapper_rva": f"0x{rva:X}",
                        "call_target_rva": f"0x{target_rva:X}",
                    })
                j += 1

            # 3. SigVerifyFunc prologue + cookie check (C-speed bytes.find)
            cookie_skip = 7
            s_total = len(SIGFUNC_PROLOGUE) + cookie_skip + len(SIGFUNC_POST_COOKIE)
            j = 0
            while True:
                j = edata.find(SIGFUNC_PROLOGUE, j)
                if j == -1 or j + s_total > len(edata):
                    break
                post_off = j + len(SIGFUNC_PROLOGUE) + cookie_skip
                if edata[post_off : post_off + len(SIGFUNC_POST_COOKIE)] == SIGFUNC_POST_COOKIE:
                    rva = sec["rva"] + j
                    sigfunc_hits.append({"section": sec["name"], "rva": f"0x{rva:X}", "va": f"0x{img_base + rva:X}"})
                j += 1

    # Source / Binary API & String indicators (SChannel, WinHTTP, WinINet, OpenSSL, BCrypt/NCrypt, .NET/Go/Rust/JVM)
    tls_indicators = []
    for marker in (
        b"DecryptMessage", b"WinHttpReadData", b"WinHttpQueryHeaders", b"InternetReadFile",
        b"HttpQueryInfo", b"SSL_read", b"SSL_read_ex", b"BCryptVerifySignature", b"BCryptDecrypt",
        b"NCryptVerifySignature", b"NCryptDecrypt", b"CryptVerifySignature", b"CryptDecrypt",
        b"CertVerifyCertificateChainPolicy", b"WinVerifyTrust", b"EVP_DigestVerifyFinal",
        b"ED25519_verify", b"x-signature-ed25519", b"NtGetContextThread", b"NtSetContextThread",
        b"MapViewOfFile", b"Go buildinf:", b"crypto/tls.(*Conn).Read", b"rustls", b"ring::signature",
        b"mscoree.dll", b"coreclr.dll", b"SslStream", b"jvm.dll", b"sunmscapi",
    ):
        if marker in raw:
            tls_indicators.append(marker.decode("ascii"))

    return {
        "target": os.path.basename(target_path),
        "is_pe": is_pe,
        "vmp_protected": len(vmp_sections) > 0,
        "vmp_sections": vmp_sections,
        "recommended_hook_mode": "HWBP (DR0/DR1 + VEH + NtGetContextThread Cloak)" if vmp_sections else "MinHook / IAT Hook",
        "libsodium_ed25519_prologues": sodium_hits,
        "libsodium_wrappers": wrapper_hits,
        "sigverify_prologues": sigfunc_hits,
        "tls_and_crypto_markers": tls_indicators,
    }


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "native_tls_hwbp"


def audit_pe_auth_tls(target_path: str, raw_data: bytes | None = None) -> dict[str, Any]:
    """Runs unified PE/Source Auth, TLS Plaintext, Ed25519 Prologue, 4-Stage Verifier & IAT/Integrity Audit with single-read caching."""
    p = Path(target_path)
    if p.is_dir():
        files_report = []
        for child in sorted(p.rglob("*"))[:100]:
            if child.is_file() and not child.is_symlink() and child.suffix.lower() in (".exe", ".dll", ".cpp", ".c", ".h", ".hpp", ".vcxproj"):
                try:
                    pre = _enum_pe_sections(str(child))
                except Exception:
                    continue
                is_bin = child.suffix.lower() in (".exe", ".dll")
                files_report.append({
                    "file": str(child.relative_to(p)),
                    "crypto_prologues": scan_native_crypto_prologues(str(child), preloaded=pre),
                    "verify_detached_4stage": scan_verify_detached_4stage(str(child), preloaded=pre) if is_bin else None,
                    "iat_and_integrity_surface": audit_iat_and_integrity_surface(str(child), raw_data=pre[2]),
                    "lea_xrefs": scan_pe_lea_xrefs(str(child), preloaded=pre) if is_bin else None,
                })
        return {
            "target_directory": str(p),
            "files_scanned": len(files_report),
            "results": files_report,
        }
    elif p.is_file():
        try:
            pre = _enum_pe_sections(str(p), raw_data=raw_data)
        except Exception as exc:
            return {"error": str(exc)}
        is_bin = p.suffix.lower() in (".exe", ".dll") or pre[2][:2] == b"MZ"
        return {
            "target_file": str(p),
            "crypto_prologues": scan_native_crypto_prologues(str(p), preloaded=pre),
            "verify_detached_4stage": scan_verify_detached_4stage(str(p), preloaded=pre) if is_bin else None,
            "iat_and_integrity_surface": audit_iat_and_integrity_surface(str(p), raw_data=pre[2]),
            "lea_xrefs": scan_pe_lea_xrefs(str(p), preloaded=pre) if is_bin else None,
        }
    return {"error": f"Path not found: {target_path}"}


def export_native_tls_hwbp_tracer(output_dir: str | None = None) -> dict[str, Any]:
    """Exports the clean, zero-timebomb OmniReverse Native TLS Plaintext Dumper & HWBP/VEH Tracer C++ SDK safely (CWE-73 hardened)."""
    tpl_root = TEMPLATE_DIR.resolve()
    if output_dir:
        import tempfile
        if ".." in Path(output_dir).parts:
            return {"error": "Guvenlik Hatasi (CWE-22): Gecisli (..) dizin yollari engellendi."}
        dest = Path(output_dir).resolve()
        # Reject self-nested subdirectories inside TEMPLATE_DIR to avoid recursive rglob blowup
        if dest != tpl_root and is_safe_subpath(dest, tpl_root):
            return {"error": "Hedef disa aktarma dizini TEMPLATE_DIR alt dizini olamaz."}
        temp_root = Path(tempfile.gettempdir()).resolve()
        # Confine output inside workspace root or OS temporary directory
        if not (is_safe_subpath(dest, STUDIO_ROOT.parent) or is_safe_subpath(dest, temp_root)):
            dest = (STUDIO_ROOT / "omni_export_sdk" / sanitize_relative_filename(dest.name or "sdk")).resolve()
    else:
        dest = tpl_root

    dest.mkdir(parents=True, exist_ok=True)
    exported_files = []
    if tpl_root.is_dir():
        import shutil
        source_items = [it for it in sorted(tpl_root.rglob("*")) if it.is_file() and not it.is_symlink()]
        for item in source_items:
            rel = item.relative_to(tpl_root)
            out_f = (dest / rel).resolve()
            if not is_safe_subpath(out_f, dest):
                continue
            out_f.parent.mkdir(parents=True, exist_ok=True)
            if item.resolve() != out_f:
                shutil.copy2(item, out_f)
            exported_files.append(str(out_f))
    return {
        "status": "success",
        "sdk_directory": str(dest),
        "exported_files": exported_files,
        "features": [
            "Zero-Timebomb (NTP CheckExpiry removed)",
            "Live SChannel (DecryptMessage) & OpenSSL (SSL_read/SSL_read_ex) Plaintext Dumper (thread-safe mutex guarded)",
            "VMProtect-Safe Hardware Breakpoints (DR0/DR1 + VEH + NtGetContextThread/NtSetContextThread DR Cloak)",
            "Self-CRC File-Mapping Sync (CreateFileW / MapViewOfFile IAT Hook with VirtualQuery bounds verification)",
            "MSVC std::string (MsvcString) Private Heap Scanner",
            "Header-Only TweetNaCl Ed25519 + SHA-512 (ed25519_sign.h)",
            "CREATE_SUSPENDED Early-Process Injector & PID Loader (mshta adware popup removed)",
        ],
    }


if __name__ == "__main__":
    import io
    import json
    import sys

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    target = sys.argv[1] if len(sys.argv) > 1 else str(TEMPLATE_DIR)
    print(f"[*] OmniReverse Native TLS & HWBP Engine — Auditing: {target}")
    report = audit_pe_auth_tls(target)
    print(json.dumps(report, indent=2, ensure_ascii=False))
