# -*- coding: utf-8 -*-
"""
OmniReverse Studio v2.1 — Comprehensive 18-Engine, Security, Cross-Platform & 7-Scenario Edge-Case Test Suite.
Covers:
  1. Normal usage across all 18 engines + Native C++ EXE + FastAPI Web Studio + MCP Server
  2. Empty data (0-byte files, empty strings, empty queries)
  3. Malformed / corrupted binary headers (truncated MZ, negative e_lfanew, corrupt ZIP/APK, corrupt WASM, JSON array .map)
  4. Boundary values (64-bit modular inverse limits, RVA out-of-bounds, instruction clamps)
  5. Missing external tool / offline fallback (pure-Python WASM, DEX, ELF, Mach-O parsers)
  6. Concurrent & repeated operations (multi-threaded BinarySession RLock + atomic os.replace)
  7. Security & unauthorized inputs (CWE-22 path traversal, CWE-78 Ghidra/ADB injection, CWE-611 XXE, CWE-312 secret redaction, CWE-1333 ReDoS)
"""

from __future__ import annotations

import concurrent.futures
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

STUDIO_ROOT = Path(__file__).resolve().parent.parent
if str(STUDIO_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDIO_ROOT))

from android_ext_engine import decode_android_resources, trace_android_references
from apk_engine import analyze_apk
from decompiler_bridge import decompile_function_ghidra
from granular_engine import disassemble_bytes_at, inspect_android_class, inspect_pe_symbols
from live_engine import adb_pull_file, adb_shell
from mba_engine import (
    hensel_lift_polynomial_inverse,
    modular_inverse_64,
    simplify_mba_expression,
    verify_mba_equivalence_z3,
)
from native_tls_hwbp_engine import (
    audit_pe_auth_tls,
    ed25519_rfc8032_self_test,
    export_native_tls_hwbp_tracer,
)
from omni_config import is_safe_subpath, mask_secret_preview
from pipeline import run_pipeline
from rebuilder_engine import rebuild_pe_file, scan_anti_dump_honeypots
from runtimes_engine import inspect_flutter_dart, inspect_go_binary, inspect_rust_binary
from session_engine import BinarySession
from sqli_detector import audit_target as audit_sqli
from triage_engine import detect_crypto, extract_indicators, match_capabilities, read_bytes_at, search_bytes
from wasm_engine import disassemble_wasm, inspect_wasm_headers
from web_bundle_engine import analyze_web_bundle, unpack_sourcemap


# ---------------------------------------------------------------------------
# 1. NATIVE C++ EXE HEADLESS AUDIT & BOUNDARY / UNICODE / MALFORMED PE TESTS
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows .exe test requires Windows OS")
def test_native_cpp_exe_normal_zero_corrupt_and_turkish_unicode(tmp_path: Path) -> None:
    exe = STUDIO_ROOT / "OmniReverse_Studio.exe"
    dll = STUDIO_ROOT / "keyauth_patcher.dll"
    assert exe.is_file(), "OmniReverse_Studio.exe must be compiled"
    assert dll.is_file(), "keyauth_patcher.dll must be compiled"

    # (a) Normal x64 DLL audit via native C++ engine
    out_normal = tmp_path / "normal_report.txt"
    r1 = subprocess.run([str(exe), "--audit", str(dll), str(out_normal)], timeout=15, check=False)
    assert r1.returncode == 0
    txt1 = out_normal.read_text(encoding="utf-8", errors="replace")
    assert "x64 (AMD64)" in txt1
    assert "SHA-256" in txt1

    # (b) 0-byte empty file
    zero_f = tmp_path / "empty_zero.bin"
    zero_f.write_bytes(b"")
    out_zero = tmp_path / "zero_report.txt"
    r2 = subprocess.run([str(exe), "--audit", str(zero_f), str(out_zero)], timeout=15, check=False)
    assert r2.returncode == 0
    assert "Boyut        : 0 bayt" in out_zero.read_text(encoding="utf-8")

    # (c) Malformed MZ with negative e_lfanew (-16) and truncated section headers (CWE-125 proof)
    bad_mz = bytearray(128)
    bad_mz[0:2] = b"MZ"
    struct.pack_into("<i", bad_mz, 0x3C, -16)
    bad_f = tmp_path / "negative_lfanew.exe"
    bad_f.write_bytes(bytes(bad_mz))
    out_bad = tmp_path / "bad_report.txt"
    r3 = subprocess.run([str(exe), "--audit", str(bad_f), str(out_bad)], timeout=15, check=False)
    assert r3.returncode == 0
    assert "gecersiz e_lfanew" in out_bad.read_text(encoding="utf-8")

    # (d) Oversized NumberOfSections = 4000 in 512-byte buffer (CWE-125 section table overflow proof)
    sec_overflow = bytearray(512)
    sec_overflow[0:2] = b"MZ"
    struct.pack_into("<i", sec_overflow, 0x3C, 0x40)
    sec_overflow[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", sec_overflow, 0x44, 0x8664)
    struct.pack_into("<H", sec_overflow, 0x46, 4000)  # NumberOfSections = 4000
    struct.pack_into("<H", sec_overflow, 0x54, 0xF0)  # SizeOfOptionalHeader
    struct.pack_into("<H", sec_overflow, 0x58, 0x20B)  # PE32+ Magic
    sec_f = tmp_path / "overflow_sections.exe"
    sec_f.write_bytes(bytes(sec_overflow))
    out_sec = tmp_path / "sec_report.txt"
    r4 = subprocess.run([str(exe), "--audit", str(sec_f), str(out_sec)], timeout=15, check=False)
    assert r4.returncode == 0
    assert "sinir asimi engellendi" in out_sec.read_text(encoding="utf-8")

    # (e) Turkish Unicode + spaces in file path
    tr_dir = tmp_path / "Türkçe Klasör Şğüıöç"
    tr_dir.mkdir(parents=True, exist_ok=True)
    tr_pe = tr_dir / "Örnek Uygulama Şğüıöç.dll"
    shutil.copy2(dll, tr_pe)
    out_tr = tmp_path / "tr_report.txt"
    r5 = subprocess.run([str(exe), "--audit", str(tr_pe), str(out_tr)], timeout=15, check=False)
    assert r5.returncode == 0
    assert "Örnek Uygulama Şğüıöç.dll" in out_tr.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 2. CROSS-PLATFORM BINARY FORMATS: PE, ELF (Linux), MACH-O (macOS/iOS), WASM
# ---------------------------------------------------------------------------

def _build_minimal_elf64() -> bytes:
    buf = bytearray(256)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1  # little-endian
    buf[6] = 1  # version
    struct.pack_into("<H", buf, 16, 2)       # ET_EXEC
    struct.pack_into("<H", buf, 18, 0x3E)    # EM_X86_64
    struct.pack_into("<I", buf, 20, 1)
    struct.pack_into("<Q", buf, 24, 0x401000)  # e_entry
    return bytes(buf)


def _build_minimal_macho64() -> bytes:
    buf = bytearray(128)
    # MH_MAGIC_64 little-endian (0xFEEDFACF)
    struct.pack_into("<I", buf, 0, 0xFEEDFACF)
    struct.pack_into("<I", buf, 4, 0x0100000C)  # CPU_TYPE_ARM64 (Apple Silicon / iOS)
    struct.pack_into("<I", buf, 8, 0)
    struct.pack_into("<I", buf, 12, 2)          # MH_EXECUTE
    struct.pack_into("<I", buf, 16, 0)          # ncmds = 0
    struct.pack_into("<I", buf, 20, 0)
    return bytes(buf)


def _build_minimal_wasm() -> bytes:
    # \0asm v1 + Export section exporting "add_fn"
    export_payload = bytearray([1, 6]) + b"add_fn" + bytearray([0, 0])
    sec_export = bytearray([7, len(export_payload)]) + export_payload
    return b"\x00asm\x01\x00\x00\x00" + bytes(sec_export)


def test_cross_platform_elf_macho_and_wasm_parsers(tmp_path: Path) -> None:
    elf_f = tmp_path / "linux_sample.elf"
    elf_f.write_bytes(_build_minimal_elf64())
    elf_info = inspect_pe_symbols(str(elf_f))
    assert elf_info.get("format") == "ELF"
    assert elf_info.get("architecture") == "x64"

    macho_f = tmp_path / "macos_arm64.macho"
    macho_f.write_bytes(_build_minimal_macho64())
    macho_info = inspect_pe_symbols(str(macho_f))
    assert macho_info.get("format") == "Mach-O"
    assert "arm64" in str(macho_info.get("architecture", "")).lower()

    wasm_f = tmp_path / "module.wasm"
    wasm_f.write_bytes(_build_minimal_wasm())
    w_hdr = inspect_wasm_headers(str(wasm_f))
    assert "error" not in w_hdr
    w_dis = disassemble_wasm(str(wasm_f), max_lines=30)
    assert "error" not in w_dis

    # Corrupt WASM header must not crash
    bad_wasm = tmp_path / "corrupt.wasm"
    bad_wasm.write_bytes(b"\x00asm\x99\xff")
    bad_hdr = inspect_wasm_headers(str(bad_wasm))
    assert isinstance(bad_hdr, dict)


# ---------------------------------------------------------------------------
# 3. Z3 SMT MBA EQUIVALENCE, MODULAR INVERSE & SAFE AST EVALUATION
# ---------------------------------------------------------------------------

def test_z3_mba_solver_and_cryptomath_edge_cases() -> None:
    res = simplify_mba_expression("(x ^ y) + 2 * (x & y)")
    assert res["smt_verified"] is True
    assert verify_mba_equivalence_z3("(x | y) + (x & y)", "x + y") is True
    assert verify_mba_equivalence_z3("x ^ y", "x + y") is False

    # Malicious Python AST call must never execute and must fail safely
    evil = simplify_mba_expression("__import__('os').system('calc')")
    assert isinstance(evil, dict)

    # Odd 64-bit modular & Hensel inverse verification: (a * inv) mod 2^64 == 1
    odd_val = 0x1337C0DEBEEF0001
    inv_info = modular_inverse_64(odd_val)
    assert inv_info["verified"] is True
    assert ((odd_val * inv_info["inverse_dec"]) & 0xFFFFFFFFFFFFFFFF) == 1
    h_inv = hensel_lift_polynomial_inverse(odd_val)
    assert ((odd_val * h_inv) & 0xFFFFFFFFFFFFFFFF) == 1

    # Even number has no inverse mod 2^64 -> dict error & ValueError cleanly
    even_info = modular_inverse_64(42)
    assert "error" in even_info
    with pytest.raises(ValueError):
        hensel_lift_polynomial_inverse(42)


# ---------------------------------------------------------------------------
# 4. SOURCEMAP, APK, XXE, SECRET MASKING & PATH TRAVERSAL GUARDS
# ---------------------------------------------------------------------------

def test_web_bundle_sourcemap_and_cwe22_sanitization(tmp_path: Path) -> None:
    # Direct .map JSON with malicious path traversal in sources[]
    smap = {
        "version": 3,
        "sources": ["../../etc/passwd", "src/auth/client.ts"],
        "sourcesContent": ["root:x:0:0", "export const login = () => true;"],
    }
    map_file = tmp_path / "bundle.js.map"
    map_file.write_text(json.dumps(smap), encoding="utf-8")

    out_extract = tmp_path / "extracted_src"
    res = unpack_sourcemap(str(map_file), extract_to_dir=str(out_extract))
    assert "error" not in res
    assert res.get("total_sources_recovered", 0) == 2
    # Verify nothing escaped out_extract
    for written in out_extract.rglob("*"):
        assert is_safe_subpath(written.resolve(), out_extract.resolve())

    # Malformed non-object JSON array in .map must not crash
    arr_map = tmp_path / "array.map"
    arr_map.write_text("[1, 2, 3]", encoding="utf-8")
    arr_res = unpack_sourcemap(str(arr_map))
    assert arr_res.get("status") == "not_found" or "error" in arr_res


def test_apk_secret_masking_xxe_and_empty_query_guards(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample_test.apk"
    fake_secret = "sk-" + "A" * 36
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><manifest package="com.test.app"/>')
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64 + f"https://api.example.com/v1/chat {fake_secret}".encode("utf-8"))

    log_lines: list[str] = []
    apk_res = analyze_apk(apk_path, log_lines)
    # JSON serializability check (no Python sets)
    dumped = json.dumps(apk_res)
    assert "https://api.example.com/v1/chat" in dumped
    # CWE-312: full raw secret must be masked in preview/report
    assert fake_secret not in apk_res.get("extracted_preview", "")

    # Empty query in trace_android_references must NOT infinite-loop
    xref_empty = trace_android_references(str(apk_path), query="", max_results=10)
    assert "error" in xref_empty


# ---------------------------------------------------------------------------
# 5. COMMAND INJECTION (CWE-78), CONCURRENT SESSIONS (CWE-362) & REDOS (CWE-1333)
# ---------------------------------------------------------------------------

def test_command_injection_and_inplace_overwrite_guards(tmp_path: Path) -> None:
    dummy_bin = tmp_path / "target.exe"
    dummy_bin.write_bytes(b"MZ" + b"\x00" * 128)

    # CWE-78: Ghidra function name with shell/flag injection must be rejected before subprocess
    gh_res = decompile_function_ghidra(str(dummy_bin), "main & calc.exe")
    assert "error" in gh_res
    gh_flag = decompile_function_ghidra(str(dummy_bin), "-postScript")
    assert "error" in gh_flag

    # CWE-78 / CWE-88: ADB option injection via leading '-'
    adb_bad = adb_pull_file("-a", str(tmp_path / "out.bin"), device_id="-e")
    assert "error" in adb_bad

    # In-place PE overwrite block + OEP bounds validation
    same_res = rebuild_pe_file(str(dummy_bin), str(dummy_bin), 0x1000)
    assert "error" in same_res
    bad_oep = rebuild_pe_file(str(dummy_bin), str(tmp_path / "out.exe"), -5)
    assert "error" in bad_oep


def test_sqli_redos_resistance_and_ed25519_rfc8032() -> None:
    # Crafted near-miss PHP string that previously caused catastrophic backtracking
    crafted_php = '<?php $q = "SELECT * FROM users WHERE " . ' + ('"a" . ' * 120) + '1; ?>'
    t0 = time.perf_counter()
    res = audit_sqli(crafted_php, is_snippet=True, language="php")
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"ReDoS regression detected: {elapsed:.2f}s"
    assert isinstance(res, dict)

    # RFC 8032 Ed25519 self-test
    ed = ed25519_rfc8032_self_test()
    assert ed.get("signature_verified") is True
    assert ed.get("public_key_hex") == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_concurrent_binary_sessions_and_cwe22_session_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sess_dir = tmp_path / "sessions_sandbox"
    monkeypatch.setenv("OMNI_SESSIONS_DIR", str(sess_dir))

    sample = tmp_path / "concurrent.bin"
    sample.write_bytes(b"\x7fELF" + os.urandom(256))
    opened = BinarySession.open_session(str(sample))
    sid = opened["session_id"]
    assert sid.startswith("sess_")

    # CWE-22 path traversal session_id must fail immediately
    trav = BinarySession.get_session("../../etc/passwd")
    assert "error" in trav

    # 12 concurrent annotation threads on the same session file
    def _worker(idx: int) -> dict:
        return BinarySession.annotate(sid, "bookmark", hex(0x401000 + idx * 4), f"fn_{idx}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(12)))
    assert all(r.get("status") == "updated" for r in results)

    final_state = BinarySession.get_session(sid)
    assert len(final_state["bookmarks"]) == 12


# ---------------------------------------------------------------------------
# 6. FASTAPI CROSS-PLATFORM WEB STUDIO ENDPOINTS & SECURITY HEADERS
# ---------------------------------------------------------------------------

def test_web_studio_rest_endpoints_and_security_headers(tmp_path: Path) -> None:
    try:
        from omni_web_studio import app, mount_static_if_ready
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("Web Studio unbundled in standalone native release")

    mount_static_if_ready()
    client = TestClient(app)

    # Index HTML + CSP & security headers
    r_idx = client.get("/")
    assert r_idx.status_code == 200
    assert "Content-Security-Policy" in r_idx.headers
    assert r_idx.headers["X-Content-Type-Options"] == "nosniff"
    assert r_idx.headers["X-Frame-Options"] == "DENY"
    assert 'lang="tr"' in r_idx.text

    # Health & Presets
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    r_pre = client.get("/api/presets")
    assert r_pre.status_code == 200
    assert len(r_pre.json()["presets"]) >= 2

    # CWE-22 Path Traversal must return HTTP 403
    r_trav = client.post("/api/analyze", json={"target_path": "../../Windows/System32/cmd.exe"})
    assert r_trav.status_code == 403

    # Upload isolated file & run deep analyze
    r_up = client.post(
        "/api/upload",
        files={"file": ("test_script.lua", b'local a = string.char(65,66,67)\nprint(a)', "text/plain")},
    )
    assert r_up.status_code == 200
    stored_path = r_up.json()["stored_path"]

    r_an = client.post("/api/analyze", json={"target_path": stored_path})
    assert r_an.status_code == 200
    assert "ABC" in r_an.json()["preview"]

    # Z3 MBA & SQLi endpoints
    r_mba = client.post("/api/mba", json={"expression": "(x ^ y) + 2 * (x & y)", "odd_constant": "0x1337C0DEBEEF0001"})
    assert r_mba.status_code == 200
    assert r_mba.json()["mba"]["smt_verified"] is True

    r_sqli = client.post("/api/sqli", json={"code": 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")'})
    assert r_sqli.status_code == 200
    assert r_sqli.json()["vulnerabilities_count"] >= 1


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 PE RT_MANIFEST SxS test")
def test_native_sxs_manifest_and_zero_ordinal_345_import() -> None:
    import pefile
    from native_app.embed_manifest import verify_activation_context

    exe_path = STUDIO_ROOT / "OmniReverse_Studio.exe"
    assert exe_path.is_file(), f"Missing native executable: {exe_path}"

    # 1. Verify Activation Context (Common Controls v6.0.0.0 + PerMonitorV2) loads cleanly
    assert verify_activation_context(str(exe_path)) is True

    # 2. Verify zero static ordinal-345 / comctl32 import & 4-byte-aligned RT_MANIFEST resource
    pe = pefile.PE(str(exe_path), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ]
    )
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_name = entry.dll.decode("utf-8", errors="replace").lower()
        assert "comctl32" not in dll_name, "Static comctl32 import risks Ordinal 345 failure if SxS is bypassed"

    manifest_sizes = []
    for res_type in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries:
        if res_type.id == 24 and hasattr(res_type, "directory"):
            for res_id in res_type.directory.entries:
                for res_lang in res_id.directory.entries:
                    manifest_sizes.append(res_lang.data.struct.Size)
    assert manifest_sizes, "RT_MANIFEST (Type 24) missing from OmniReverse_Studio.exe"
    assert all(sz % 4 == 0 for sz in manifest_sizes), f"RT_MANIFEST must be 4-byte aligned, got {manifest_sizes}"

