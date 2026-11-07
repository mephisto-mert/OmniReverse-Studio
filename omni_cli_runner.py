# -*- coding: utf-8 -*-
"""
OmniReverse Studio Unified CLI Bridge (omni_cli_runner.py)
Exposes all 18 OmniReverse Studio engines to the Native x64 C++ GUI (OmniReverse_Studio.exe).
"""
import sys
import io
import os
import json
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from omni_config import safe_read_binary

from pipeline import run_pipeline
from triage_engine import match_capabilities, extract_indicators, detect_crypto, read_bytes_at
from native_tls_hwbp_engine import (
    audit_pe_auth_tls,
    scan_pe_lea_xrefs,
    scan_native_crypto_prologues,
    export_native_tls_hwbp_tracer,
    ed25519_rfc8032_self_test,
)
from granular_engine import inspect_pe_symbols, disassemble_bytes_at, inspect_android_class
from runtimes_engine import inspect_go_binary, inspect_rust_binary, inspect_flutter_dart
from rebuilder_engine import scan_anti_dump_honeypots
from mba_engine import simplify_mba_expression, modular_inverse_64
from emulator_engine import emulate_pe_range
from live_engine import frida_list_devices, adb_list_devices
from sqli_detector import audit_target as audit_sqli
from wasm_engine import inspect_wasm_headers, disassemble_wasm
from web_bundle_engine import analyze_web_bundle, unpack_sourcemap
from android_ext_engine import trace_android_references, decode_android_resources
from session_engine import BinarySession


def run_full_omnireverse_suite(target_path: str, mode: str = "all", extra_arg: str = "") -> None:
    p = Path(target_path)
    print("========================================================================")
    print(f"  OMNIREVERSE STUDIO - TAM MOTOR ANALIZI (MOD: {mode.upper()})")
    print(f"  Hedef: {target_path}")
    print("========================================================================\n")

    if mode == "sqli":
        res = audit_sqli(target_path, is_snippet=False)
        print(res.get("report_markdown", json.dumps(res, indent=2, ensure_ascii=False)))
        return

    if mode == "sdk_and_tools":
        print("## 1. Standalone C++ Native TLS & HWBP/VEH Tracer SDK Dışa Aktarımı")
        sdk_res = export_native_tls_hwbp_tracer(target_path if target_path else None)
        print(json.dumps(sdk_res, indent=2, ensure_ascii=False))
        print("\n## 2. RFC 8032 Ed25519 + SHA-512 (ed25519_sign.h) İmzalama & Doğrulama Testi")
        ed_res = ed25519_rfc8032_self_test()
        print(json.dumps(ed_res, indent=2, ensure_ascii=False))
        print("\n## 3. Z3 MBA İfade Sadeleştirici & 64-Bit Modüler Ters (Modular Inverse) Motoru")
        mba_res = simplify_mba_expression("(x ^ y) + 2 * (x & y)")
        inv_res = modular_inverse_64(0x1337C0DEBEEF0001)
        print(json.dumps({"mba_simplification": mba_res, "modular_inverse_64": inv_res}, indent=2, ensure_ascii=False))
        print("\n## 4. Canlı Frida & ADB Cihaz Taraması")
        print(json.dumps({"frida_devices": frida_list_devices(), "adb_devices": adb_list_devices()}, indent=2, ensure_ascii=False))
        return

    if not p.exists():
        print(f"[!] Hata: Hedef bulunamadi -> {target_path}")
        return

    if p.is_dir():
        print("[*] Klasor Taramasi (TLS/Kripto Prolog & SQLi SAST Denetimi)...")
        tls_dir = audit_pe_auth_tls(target_path)
        print(json.dumps(tls_dir, indent=2, ensure_ascii=False))
        sqli_dir = audit_sqli(target_path, is_snippet=False)
        print("\n" + sqli_dir.get("report_markdown", ""))
        return

    # 1. Open/Update Stateful Session
    try:
        sess = BinarySession.open_session(str(p))
        sess_data = sess.get("data") or {}
        sha_disp = sess_data.get("sha256") or sess_data.get("sha256_prefix") or ""
        print(f"[+] Oturum (Session) Acildi: {sess.get('session_id')} (SHA256: {sha_disp[:16]}...)\n")
    except Exception:
        pass

    # 2. 5-Stage Deep Reverse Pipeline (safe static mode by default)
    cached_tls: dict | None = None
    if mode in ("all", "deep"):
        try:
            rep = run_pipeline(str(p), allow_live_execution=False)
            cached_tls = rep.native_tls_audit or None
            print(rep.to_markdown())
        except Exception as e:
            print(f"[!] Pipeline Uyarisi: {e}")

    # 3. Native TLS, libsodium Ed25519 Prologues & RIP-Relative LEA/Jcc Branches (reuse pipeline cache when available)
    if mode in ("all", "deep", "tls"):
        try:
            print("\n## Native TLS, Ed25519 Prolog & RIP-Bağıl LEA/Jcc Dallanma Denetimi")
            tls_res = cached_tls if cached_tls else audit_pe_auth_tls(str(p))
            print(json.dumps(tls_res, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"[!] Native TLS Audit Uyarisi: {e}")

    # 4. Granular Runtime & Symbol Recovery (PE / Go / Rust / Flutter / Honeypots / Capstone)
    ext = p.suffix.lower()
    if mode in ("all", "deep", "granular"):
        if ext in (".exe", ".dll", ".sys"):
            try:
                print("\n## PE Sembol, İçe/Dışa Aktarma & Anti-Dump Honeypot Analizi")
                sym = inspect_pe_symbols(str(p))
                hp = scan_anti_dump_honeypots(str(p))
                go_info = inspect_go_binary(str(p))
                rust_info = inspect_rust_binary(str(p))
                imp_data = sym.get("imports", {})
                sample_imps = list(imp_data.keys())[:25] if isinstance(imp_data, dict) else imp_data[:25]
                print(json.dumps({
                    "pe_symbols_summary": {
                        "architecture": sym.get("architecture"),
                        "entry_point": sym.get("entry_point"),
                        "import_modules_count": len(imp_data),
                        "exports_count": sym.get("export_count", len(sym.get("exports", []))),
                        "import_modules": sample_imps,
                    },
                    "anti_dump_honeypots": hp,
                    "go_runtime": go_info if go_info.get("is_go") else "Not Go",
                    "rust_runtime": rust_info if rust_info.get("is_rust") else "Not Rust",
                }, indent=2, ensure_ascii=False))
                ep_str = sym.get("entry_point", "")
                if ep_str and str(ep_str).startswith("0x"):
                    ep_va = int(ep_str, 16)
                    print("\n## EntryPoint Capstone Disassembly & Pseudocode Analizi")
                    dis = disassemble_bytes_at(str(p), ep_va, is_va=True, instruction_count=20)
                    print(json.dumps(dis, indent=2, ensure_ascii=False))
                    real_va_str = dis.get("base_address", ep_str)
                    real_va = int(str(real_va_str), 16) if str(real_va_str).startswith("0x") else ep_va
                    print("\n## Unicorn CPU Emülasyonu (EntryPoint İlk 100 Komut & CMP Yakalama)")
                    emu = emulate_pe_range(str(p), real_va, real_va + 0x200, max_instructions=100)
                    print(json.dumps(emu, indent=2, ensure_ascii=False))
            except Exception as e:
                print(f"[!] Granular PE Uyarisi: {e}")

        elif ext in (".py", ".php", ".rb", ".go", ".java", ".cs", ".cpp", ".c", ".h", ".ts", ".lua"):
            try:
                print("\n## Kaynak Kod SAST & AST SQLi / Sır Taraması")
                sqli_res = audit_sqli(str(p), is_snippet=False)
                print(sqli_res.get("report_markdown", json.dumps(sqli_res, indent=2, ensure_ascii=False)))
            except Exception as e:
                print(f"[!] SAST Uyarisi: {e}")

        elif ext == ".apk":
            try:
                print("\n## Android APK ARSC Kaynak, XRef & Flutter/Dart Analizi")
                arsc = decode_android_resources(str(p), max_strings=40)
                xref = trace_android_references(str(p), query=extra_arg or "api", max_results=20)
                flut = inspect_flutter_dart(str(p))
                print(json.dumps({"arsc_resources": arsc, "xrefs": xref, "flutter": flut}, indent=2, ensure_ascii=False))
            except Exception as e:
                print(f"[!] APK Granular Uyarisi: {e}")

        elif ext == ".wasm":
            print("\n## WebAssembly (WABT) Başlık & Disassembly Analizi")
            print(json.dumps(inspect_wasm_headers(str(p)), indent=2, ensure_ascii=False))
            print(json.dumps(disassemble_wasm(str(p), max_lines=80), indent=2, ensure_ascii=False))

        elif ext in (".js", ".map"):
            print("\n## Web Bundle & Sourcemap Analizi")
            if ext == ".map":
                print(json.dumps(unpack_sourcemap(str(p)), indent=2, ensure_ascii=False))
            else:
                print(json.dumps(analyze_web_bundle(str(p)), indent=2, ensure_ascii=False))

    # 5. Dynamic Memory Unpacker & Unicorn CPU Emulation (when mode == 'unpack')
    if mode == "unpack" and ext in (".exe", ".dll"):
        print("\n## Canlı Bellek Unpacker (RAM Dump + LCG String + VM Bytecode) & Unicorn Emülasyonu")
        try:
            from dynamic_unpacker import run_dynamic_memory_unpack
            dump_res = run_dynamic_memory_unpack(str(p), wait_time_sec=2.0)
            print(json.dumps(dump_res, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"[!] Dynamic Unpacker Uyarisi: {e}")

    # 6. v3.0 Elite Reverse Suite (20 New Engines: .NET, IAT, Syscalls, YARA, Mobile Deep, Modern Packers, CFG, Protobuf)
    if mode in ("all", "v3_suite"):
        print("\n## OmniReverse v3.0 Elite Motor Taraması (.NET / Syscall / YARA / Mobil / Paketleyici / CFG / Protobuf)")
        v3_report: dict[str, object] = {}
        try:
            from native_packer_engine import inspect_dotnet_cil, reconstruct_iat_scylla, scan_direct_syscalls, synthesize_yara_and_crypto
            from modern_packers_engine import extract_node_bun_sea, unpack_electron_asar, unpack_python_frozen
            from symbolic_protocol_engine import recover_protobuf_schemas, unflatten_ollvm_cfg
            from visual_patch_memory_engine import build_visual_cfg, hex_view_and_patch

            v3_report["yara_and_crypto"] = synthesize_yara_and_crypto(str(p))
            v3_report["protobuf_schemas"] = recover_protobuf_schemas(str(p))
            v3_report["hex_preview"] = hex_view_and_patch(str(p), offset_or_va=0, length=64)

            if ext in (".exe", ".dll", ".sys"):
                v3_report["dotnet_cil"] = inspect_dotnet_cil(str(p))
                v3_report["iat_scylla"] = reconstruct_iat_scylla(str(p))
                v3_report["direct_syscalls"] = scan_direct_syscalls(str(p))
                v3_report["python_frozen"] = unpack_python_frozen(str(p))
                v3_report["node_bun_sea"] = extract_node_bun_sea(str(p))
                cfg_res = build_visual_cfg(str(p), max_instructions=60)
                cfg_res.pop("svg", None)
                v3_report["visual_cfg_summary"] = cfg_res
                v3_report["ollvm_cff"] = unflatten_ollvm_cfg(str(p), max_instructions=120)
            elif ext in (".apk", ".ipa", ".so", ".hbc", ".dat"):
                from mobile_deep_engine import (
                    analyze_flutter_aot_snapshot,
                    analyze_ios_ipa_macho,
                    decompile_hermes_bytecode,
                    dump_unity_il2cpp,
                    generate_frida_bypass_bundle,
                )
                v3_report["flutter_aot"] = analyze_flutter_aot_snapshot(str(p))
                v3_report["hermes_hbc"] = decompile_hermes_bytecode(str(p))
                v3_report["unity_il2cpp"] = dump_unity_il2cpp(str(p))
                if ext == ".ipa":
                    v3_report["ios_ipa_macho"] = analyze_ios_ipa_macho(str(p))
                v3_report["frida_bypass"] = generate_frida_bypass_bundle("all")
            elif ext in (".asar", ".jsc"):
                v3_report["electron_asar"] = unpack_electron_asar(str(p))
            elif ext == ".pyc":
                v3_report["python_pyc"] = unpack_python_frozen(str(p))
            print(json.dumps(v3_report, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"[!] v3.0 Elite Suite Uyarisi: {e}")


def export_html_audit_report(target_path: str, output_path: str) -> str:
    """Exports a self-contained single-file HTML audit report."""
    from report_generator import generate_html_report
    from pipeline import run_pipeline, entropy

    p = Path(target_path)
    if not p.exists():
        print(f"[!] Target not found: {target_path}")
        return ""

    raw = safe_read_binary(str(p), max_bytes=10_000_000) or b""
    triage_data = {
        "sha256": hashlib.sha256(raw).hexdigest() if raw else "N/A",
        "format": p.suffix.upper().lstrip(".") or "Binary",
        "entropy": round(entropy(raw), 3) if raw else 0.0,
        "crypto": [],
        "syscalls": [],
        "strings": [],
    }

    try:
        rep = run_pipeline(str(p), allow_live_execution=False)
        triage_data["sha256"] = rep.sha256 or triage_data["sha256"]
        triage_data["format"] = rep.format or triage_data["format"]
        triage_data["entropy"] = rep.entropy or triage_data["entropy"]
        triage_data["crypto"] = rep.crypto_signatures or []
        triage_data["strings"] = rep.interesting_strings[:40] if hasattr(rep, "interesting_strings") and rep.interesting_strings else []
    except Exception:
        pass

    try:
        from visual_patch_memory_engine import build_visual_cfg
        cfg = build_visual_cfg(str(p), max_instructions=40)
        if isinstance(cfg, dict) and "svg" in cfg:
            triage_data["cfg_svg"] = cfg["svg"]
    except Exception:
        pass

    try:
        from native_packer_engine import scan_direct_syscalls
        sc = scan_direct_syscalls(str(p))
        if isinstance(sc, dict) and "syscalls" in sc:
            triage_data["syscalls"] = [s.get("name", "") for s in sc.get("syscalls", [])]
    except Exception:
        pass

    html = generate_html_report(str(p), triage_data, output_path=output_path)
    print(f"[+] Standalone HTML Report exported to: {output_path}")
    return html


def main() -> int:
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    args = sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        print("OmniReverse Studio CLI v3.2.0")
        print("Usage: omni <target> [--mode <all|deep|tls|granular|sqli|v3_suite>] [--export-html <output.html>]")
        return 0

    target = ""
    mode_arg = "all"
    extra = ""
    export_html_path = ""

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--mode", "-m") and i + 1 < len(args):
            mode_arg = args[i + 1]
            i += 2
        elif arg in ("--export-html", "-o") and i + 1 < len(args):
            export_html_path = args[i + 1]
            i += 2
        elif not target and not arg.startswith("-"):
            target = arg
            i += 1
        elif not extra and not arg.startswith("-"):
            extra = arg
            i += 1
        else:
            i += 1

    run_full_omnireverse_suite(target, mode=mode_arg, extra_arg=extra)

    if export_html_path and target:
        export_html_audit_report(target, export_html_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
