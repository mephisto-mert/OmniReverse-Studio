#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OmniReverse MCP Server (omni_server.py)
Unified Reverse Engineering & Deobfuscation Pipeline Bridge for Antigravity & AI Agents.
Combines:
- Nyx Deobfuscator Engine (CFF, Opaque Predicates, Protectors, Crypto Signatures)
- REA / Ghidra / JADX Ecosystem (PE, ELF, APK, Function Maps, Disassembly)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from pipeline import run_pipeline

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "omni-reverse"
SERVER_VERSION = "3.2.0"

TOOLS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "omni_deep_reverse",
        "description": "Execute the full unified reverse engineering pipeline on a file (.exe, .dll, .lua, .js, .py, .apk, .luac). Detects protectors, unrolls obfuscation, disassembles, and exports clean source code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute filesystem path to the file to reverse engineer."
                },
                "aggressive": {
                    "type": "boolean",
                    "description": "Apply deep multi-pass deobfuscation. Default true.",
                    "default": True
                },
                "beautify": {
                    "type": "boolean",
                    "description": "Format and beautify the output. Default true.",
                    "default": True
                },
                "format": {
                    "type": "string",
                    "description": "Output report format: 'markdown' or 'json'. Default 'markdown'.",
                    "enum": ["markdown", "json"],
                    "default": "markdown"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "omni_deobfuscate_snippet",
        "description": "Instant deobfuscation of a Lua, JavaScript, or Python code string. Strips CFF loops, resolves string tables, and formats clean source code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The obfuscated source code string."
                },
                "language": {
                    "type": "string",
                    "description": "Language: 'auto', 'lua', 'javascript', 'python'. Default 'auto'.",
                    "enum": ["auto", "lua", "javascript", "python"],
                    "default": "auto"
                }
            },
            "required": ["code"]
        }
    },
    {
        "name": "omni_triage_target",
        "description": "Fast reconnaissance on a target file: detects format, architecture, entropy, compiler, packers, and 25+ protector signatures without full decompilation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the target file."
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "omni_audit_sqli",
        "description": "AST-based Static Application Security Testing (SAST) to audit Python, JS, PHP, or Java code/files for SQL Injection (SQLi) vulnerabilities and unparameterized query sinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the source file or directory to scan for SQLi."
                },
                "code": {
                    "type": "string",
                    "description": "Optional raw code snippet to scan directly."
                },
                "language": {
                    "type": "string",
                    "description": "Language: 'auto', 'python', 'javascript', 'php', 'java'. Default 'auto'.",
                    "enum": ["auto", "python", "javascript", "php", "java"],
                    "default": "auto"
                }
            }
        }
    },
    {
        "name": "omni_inspect_symbol",
        "description": "Granular reverse engineering & cryptanalysis: inspect PE symbols, disassemble with Capstone, decompile Java with JADX, decompile C with Ghidra, recover Go/Rust/Flutter symbols, simplify MBA expressions with Z3, compute Hensel lifting / modular inverses, rebuild unpacked PEs, detect honeypot traps, read bytes/RVAs, search byte patterns, detect crypto constant tables, extract structured IoC indicators, disassemble WASM modules via WABT, unpack web sourcemaps, and extract Android XRef/resources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Path to target binary (.exe, .dll, .apk, .so, .dex, .wasm, .js)."
                },
                "action": {
                    "type": "string",
                    "description": "Inspection action: 'pe_symbols', 'disassemble_address', 'android_class', 'pseudo_c', 'go_symbols', 'rust_metadata', 'flutter_dart', 'simplify_mba', 'hensel_inverse', 'modular_inverse', 'rebuild_pe', 'scan_honeypots', 'read_bytes', 'read_rva', 'search_bytes', 'crypto_signatures', 'indicators', 'capabilities', 'wasm_disasm', 'wasm_headers', 'unpack_sourcemap', 'analyze_web_bundle', 'android_xref', 'android_resources', 'pe_lea_xrefs', 'native_crypto_prologues'.",
                    "enum": ["pe_symbols", "disassemble_address", "android_class", "pseudo_c", "go_symbols", "rust_metadata", "flutter_dart", "simplify_mba", "hensel_inverse", "modular_inverse", "rebuild_pe", "scan_honeypots", "read_bytes", "read_rva", "search_bytes", "crypto_signatures", "indicators", "capabilities", "wasm_disasm", "wasm_headers", "unpack_sourcemap", "analyze_web_bundle", "android_xref", "android_resources", "pe_lea_xrefs", "native_crypto_prologues"],
                    "default": "pe_symbols"
                },
                "query": {
                    "type": "string",
                    "description": "Address/offset (e.g. '0x140001000' or RVA) for disassembly/pseudo_c/rebuild_pe/read_bytes/read_rva, search pattern (hex '55 48 89 E5' or 'str:admin'), MBA expression, hex value for modular/Hensel inverse, or Java class name."
                },
                "arch": {
                    "type": "string",
                    "description": "Architecture for disassembly: 'x64', 'x86', 'arm64', 'arm'. Default 'x64'.",
                    "enum": ["x64", "x86", "arm64", "arm"],
                    "default": "x64"
                },
                "count": {
                    "type": "integer",
                    "description": "Number of instructions to disassemble (default 25).",
                    "default": 25
                }
            },
            "required": ["target_path", "action"]
        }
    },
    {
        "name": "omni_dynamic_probe",
        "description": "Live dynamic instrumentation, memory dumping & CPU emulation: Win32 dynamic memory unrolling (Themida/VMProtect/Crypters), Unicorn x86/x64 instruction tracing, Frida script hooking, and ADB device control.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action: 'memory_dump' (dump RAM & decrypt LCG strings/VM from running packed process), 'unicorn_emulate', 'frida_devices', 'frida_processes', 'frida_inject', 'adb_devices', 'adb_shell', 'adb_pull', 'adb_logcat'.",
                    "enum": ["memory_dump", "dynamic_unpack", "unicorn_emulate", "frida_devices", "frida_processes", "frida_inject", "adb_devices", "adb_shell", "adb_pull", "adb_logcat"]
                },
                "target": {
                    "type": "string",
                    "description": "Target PE path (for unicorn_emulate), PID, process name, device ID, or remote path."
                },
                "payload": {
                    "type": "string",
                    "description": "Emulation range 'start_va:end_va' (e.g. '0x140001000:0x140001200'), Frida JavaScript script payload, shell command string, or local destination path."
                },
                "timeout": {
                    "type": "number",
                    "description": "Execution timeout or max instructions (default 5.0 / 10000).",
                    "default": 5.0
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "omni_session",
        "description": "Stateful reverse engineering session manager: open binary projects, persist bookmarks, function comments, symbol renaming, and query active analysis state across turns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Session action: 'open', 'annotate', 'get', 'list'.",
                    "enum": ["open", "annotate", "get", "list"]
                },
                "target_path": {
                    "type": "string",
                    "description": "Target file path (required for 'open')."
                },
                "session_id": {
                    "type": "string",
                    "description": "Active session ID (e.g. 'sess_...')."
                },
                "annotation_type": {
                    "type": "string",
                    "description": "Type of annotation: 'bookmark', 'comment', 'rename_symbol', 'note'.",
                    "enum": ["bookmark", "comment", "rename_symbol", "note"]
                },
                "address": {
                    "type": "string",
                    "description": "Address or symbol key for annotation."
                },
                "value": {
                    "type": "string",
                    "description": "Annotation text, label, or renamed symbol value."
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "omni_native_tls_tracer",
        "description": "Native Windows x64 TLS Plaintext Interceptor (SChannel DecryptMessage / OpenSSL SSL_read), VMProtect-safe Hardware Breakpoint (DR0/DR1 + VEH + NtGetContextThread Cloak), RIP-relative LEA + CALL/TEST/Jcc Branch Scanner, libsodium/Ed25519 Prologue Auditor & C++ Tracer SDK Exporter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action: 'audit_target' (full PE/source TLS, Ed25519 prologue, 4-stage verifier, IAT/Self-CRC/Timebomb & LEA branch audit), 'scan_lea_xrefs' (locate strings, RIP-relative LEA refs & 4-pattern JE/JNE branches), 'scan_crypto_prologues' (detect libsodium Ed25519 prologues, wrappers & .vmp sections), 'scan_verify_4stage' (Priority 0/1/2/3 hierarchical verifier & 512B backward CALL+TEST scanner), 'audit_iat_integrity' (IAT FirstThunk slot VAs, MsvcString SSO scan, Self-CRC MapViewOfFile, Anti-HWBP NtGetContextThread, TLS coalescing, 0xC0DEBABE NTP timebomb & mshta adware audit), 'ed25519_self_test' (RFC 8032 Ed25519 + SHA-512 detached sign/verify test), 'export_tracer_sdk' (export clean C++ x64 SChannel/OpenSSL plaintext dumper & HWBP/VEH SDK).",
                    "enum": ["audit_target", "scan_lea_xrefs", "scan_crypto_prologues", "scan_verify_4stage", "audit_iat_integrity", "ed25519_self_test", "export_tracer_sdk"],
                    "default": "audit_target"
                },
                "target_path": {
                    "type": "string",
                    "description": "Path to target PE/source file or directory (for audit/scan), or output directory (for export_tracer_sdk)."
                },
                "query": {
                    "type": "string",
                    "description": "Optional target string needle for 'scan_lea_xrefs'."
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "omni_advanced_native",
        "description": "Advanced Native & .NET Reverse Engineering: ECMA-335 .NET CIL/BSJB metadata & Costura.Fody unpacker, Scylla-style IAT thunk reconstructor, Hell's Gate / SysWhispers direct syscall scanner, automated YARA + Crypto S-Box synthesizer, and structural BinDiff patch comparator.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["dotnet_cil", "iat_scylla", "direct_syscalls", "yara_crypto", "bindiff"],
                    "description": "Native analysis action to run."
                },
                "target_path": {
                    "type": "string",
                    "description": "Primary binary path (.exe, .dll, .so, .elf, .dylib)."
                },
                "secondary_path": {
                    "type": "string",
                    "description": "Second binary path (for 'bindiff') or optional export directory / YARA rule name."
                }
            },
            "required": ["action", "target_path"]
        }
    },
    {
        "name": "omni_mobile_deep",
        "description": "Deep Mobile Reverse Engineering (Android & iOS): Flutter libapp.so Dart AOT snapshot analyzer, React Native Hermes (.hbc) bytecode decoder, Unity IL2CPP (global-metadata.dat) C# symbol dumper, iOS .ipa / Mach-O / FairPlay / Swift demangler, and multi-platform Frida SSL-Pinning & Anti-Debug bypass generator.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["flutter_aot", "hermes_hbc", "unity_il2cpp", "ios_ipa_macho", "frida_bypass"],
                    "description": "Mobile reverse engineering action."
                },
                "target_path": {
                    "type": "string",
                    "description": "Path to .apk, .ipa, libapp.so, .hbc, global-metadata.dat, Mach-O, or package name (for frida_bypass)."
                },
                "profile_or_meta": {
                    "type": "string",
                    "description": "Optional Frida profile ('all', 'ssl_pinning', 'anti_debug', 'root_jailbreak') or secondary metadata path."
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "omni_modern_unpacker",
        "description": "Modern Application Packager Unpacker: Electron app.asar virtual filesystem & V8 bytecode (.jsc) unpacker, Python frozen binary unpacker (PyInstaller MEI CArchive, Nuitka, PyArmor, .pyc disassembler), and Node.js SEA / Vercel pkg / Bun standalone JS bundle extractor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["electron_asar", "python_frozen", "node_bun_sea"],
                    "description": "Modern application unpacker engine."
                },
                "target_path": {
                    "type": "string",
                    "description": "Path to app.asar, .jsc, frozen .exe, or .pyc file."
                },
                "extract_dir": {
                    "type": "string",
                    "description": "Optional safe export directory inside workspace."
                }
            },
            "required": ["action", "target_path"]
        }
    },
    {
        "name": "omni_symbolic_protocol",
        "description": "Symbolic Solving, OLLVM Deobfuscation & Protocol Synthesis: Z3 SMT symbolic serial/keygen solver, OLLVM Control-Flow Flattening (CFF) dispatcher unflattener, Chrome-124 stealth curl_cffi Python client generator, and embedded Protobuf / gRPC .proto schema recoverer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["z3_keygen", "ollvm_unflatten", "generate_client", "protobuf_recover"],
                    "description": "Symbolic or protocol synthesis action."
                },
                "target_or_expr": {
                    "type": "string",
                    "description": "Z3 byte constraint expression (e.g. 'b[0] ^ 0x42 == 0x0f; b[1] + b[2] == 150'), binary path, or API URL."
                },
                "extra": {
                    "type": "string",
                    "description": "Optional prefix (for z3_keygen), function VA/offset (for ollvm_unflatten), HTTP method (for generate_client), or output path."
                },
                "key_length": {
                    "type": "integer",
                    "default": 16,
                    "description": "Key byte length for z3_keygen (default 16)."
                }
            },
            "required": ["action", "target_or_expr"]
        }
    },
    {
        "name": "omni_patch_cfg_memory",
        "description": "Visual CFG, Binary Patcher & Live Memory/Pointer Scanner: Hex + ASCII inspector, non-destructive x86/x64 binary patcher (NOP, RET, Jcc->JMP, raw hex), Basic-Block Control Flow Graph (JSON + inline SVG), and Cheat-Engine-style live process memory value & 64-bit pointer scanner.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["hex_view", "binary_patch", "visual_cfg", "memory_scan", "pointer_scan"],
                    "description": "Visual CFG, binary patching, or live RAM scanning action."
                },
                "target": {
                    "type": "string",
                    "description": "Target binary path (for hex_view/binary_patch/visual_cfg) or live process PID (for memory_scan/pointer_scan)."
                },
                "address_or_offset": {
                    "type": "string",
                    "description": "File offset or VA (e.g. '0x400' or '0x140001000'), or target pointer VA for pointer_scan."
                },
                "patch_or_value": {
                    "type": "string",
                    "description": "Patch spec ('nop:5', 'ret_true', 'ret_false', 'force_jmp', or hex bytes) OR memory value to scan."
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["ascii", "utf16", "int32", "uint32", "int64", "uint64", "float", "double", "hex"],
                    "default": "ascii",
                    "description": "Data type for live memory_scan."
                }
            },
            "required": ["action", "target"]
        }
    },
    {
        "name": "omni_bsim_vault",
        "description": "Local SQLite FTS5 Function Signature & Binary Fingerprint Vault (FLIRT / Ghidra BSim style): index stripped or reference library prologues, match unknown functions across binaries, and full-text search signatures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["index_binary", "match_functions", "search_vault"],
                    "description": "Vault operation to execute."
                },
                "target_path": {
                    "type": "string",
                    "description": "Binary path (for index_binary / match_functions) or search query."
                },
                "query_or_label_prefix": {
                    "type": "string",
                    "description": "Optional library prefix when indexing (e.g. 'openssl_3') or FTS5 search keyword."
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "omni_export_annotations",
        "description": "Export OmniReverse session bookmarks, comments, symbol renames, and Scylla IAT slots into ready-to-run IDAPython (.py), Ghidra (.py), Binary Ninja (.py), or x64dbg (.dd64.json) scripts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_or_target": {
                    "type": "string",
                    "description": "Session ID ('sess_...') or target binary file path."
                },
                "export_format": {
                    "type": "string",
                    "enum": ["idapython", "ghidra", "binja", "x64dbg"],
                    "default": "idapython",
                    "description": "Target reverse engineering IDE script format."
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional safe output path inside workspace."
                }
            },
            "required": ["session_or_target"]
        }
    },
    {
        "name": "omni_pdb_traffic_correlate",
        "description": "PE RSDS CodeView PDB GUID/Symbol-Server resolver, SQLCipher/DPAPI/Keystore encrypted vault header inspector, and HAR/HTTP log -> OpenAPI 3.1 Swagger schema synthesizer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["pdb_info", "vault_headers", "har_to_openapi"],
                    "description": "Correlation or inspection mode."
                },
                "target_path": {
                    "type": "string",
                    "description": "Path to PE binary, encrypted .db/vault file, or .har/.json capture."
                }
            },
            "required": ["action", "target_path"]
        }
    },
    {
        "name": "omni_auto_orchestrate",
        "description": "Autonomous Format-Aware Reverse Engineering Orchestrator: classifies any file or directory (.exe, .dll, .apk, .ipa, .asar, .pyc, .wasm, .js, source dir) by magic bytes and runs the optimal multi-engine audit chain in one call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Target file or directory path to automatically classify and analyze."
                }
            },
            "required": ["target_path"]
        }
    }
]


def _log(msg: str) -> None:
    sys.stderr.write(f"[OMNI-REVERSE] {msg}\n")
    sys.stderr.flush()


def _parse_int_arg(raw_val: Any, default: int | None = None) -> int:
    if raw_val is None or str(raw_val).strip() == "":
        if default is not None:
            return default
        raise ValueError("Sayısal parametre boş olamaz.")
    s = str(raw_val).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def _clamp_int(raw_val: Any, default: int, lo: int, hi: int) -> int:
    try:
        v = int(raw_val)
    except Exception:
        v = default
    return max(lo, min(hi, v))


def _handle_deep_reverse(args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("path", "")).strip()
    aggressive = bool(args.get("aggressive", True))
    beautify = bool(args.get("beautify", True))
    fmt = args.get("format", "markdown")

    if not path or not os.path.isfile(path):
        return {"isError": True, "content": [{"type": "text", "text": f"Hata: Dosya bulunamadi -> {path}"}]}

    report = run_pipeline(path, aggressive=aggressive, beautify=beautify, allow_live_execution=False)
    out_text = report.to_markdown() if fmt == "markdown" else json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    return {"content": [{"type": "text", "text": out_text}]}


def _handle_deobfuscate_snippet(args: dict[str, Any]) -> dict[str, Any]:
    raw_code = str(args.get("code", ""))
    if len(raw_code) > 2_000_000:
        return {"isError": True, "content": [{"type": "text", "text": "Hata: Kod parçacığı 2 MB sınırını aşıyor."}]}

    env_nyx = os.environ.get("OMNI_NYX_DIR", "").strip()
    if env_nyx and os.path.isdir(env_nyx) and env_nyx not in sys.path:
        sys.path.append(env_nyx)
    try:
        from nyx_mcp_server import _handle_deobfuscate_code
        return _handle_deobfuscate_code(args)
    except ImportError:
        import base64
        import re
        code = raw_code

        def _repl_char(m: re.Match) -> str:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            return '"' + "".join(chr(n) for n in nums if 0 <= n < 256) + '"'

        clean = re.sub(r"string\.char\(([\d,\s]+)\)", _repl_char, code)
        clean = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), clean)

        def _repl_b64(m: re.Match) -> str:
            try:
                dec = base64.b64decode(m.group(2), validate=True).decode("utf-8")
                if all(c.isprintable() or c in "\r\n\t" for c in dec):
                    return repr(dec)
            except Exception:
                pass
            return m.group(0)

        clean = re.sub(r"\b(atob|b64decode)\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)", _repl_b64, clean)
        payload = {"changed": clean != code, "clean_code": clean, "language": args.get("language", "auto")}
        return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}


def _handle_triage_target(args: dict[str, Any]) -> dict[str, Any]:
    from omni_config import safe_read_binary
    from pipeline import detect

    target_path = str(args.get("path") or "").strip()
    if not target_path or not os.path.isfile(target_path):
        return {"isError": True, "content": [{"type": "text", "text": f"Hata: Dosya bulunamadi -> {target_path}"}]}

    try:
        from triage_engine import match_capabilities, detect_crypto, extract_indicators
        data = safe_read_binary(target_path)
        det = detect(target_path, data)
        caps = match_capabilities(target_path, data)
        crypt = detect_crypto(data)
        inds = extract_indicators(data)
        payload = {
            "target": os.path.basename(target_path),
            "path": str(Path(target_path).resolve()),
            "size_bytes": len(data),
            "kind": det.kind,
            "label": det.label,
            "entropy": det.entropy,
            "protectors": list(det.obfuscators),
            "reasons": list(det.reasons),
            "capabilities": caps[:10],
            "crypto_signatures": crypt,
            "indicators_summary": inds["counts"],
        }
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": f"Triage hatasi: {e}"}]}


def _handle_audit_sqli(args: dict[str, Any]) -> dict[str, Any]:
    from sqli_detector import audit_target
    code = args.get("code")
    path = args.get("path")
    lang = args.get("language", "auto")

    if code:
        res = audit_target(code, is_snippet=True, language=lang)
    elif path:
        res = audit_target(path, is_snippet=False, language=lang)
    else:
        return {"isError": True, "content": [{"type": "text", "text": "Hata: 'path' veya 'code' parametrelerinden biri zorunludur."}]}

    return {"content": [{"type": "text", "text": res["report_markdown"]}]}


def _handle_inspect_symbol(args: dict[str, Any]) -> dict[str, Any]:
    from omni_config import safe_read_binary
    from granular_engine import disassemble_bytes_at, inspect_pe_symbols, inspect_android_class
    from decompiler_bridge import decompile_function_ghidra
    from runtimes_engine import inspect_go_binary, inspect_rust_binary, inspect_flutter_dart

    target_path = str(args.get("target_path", "")).strip()
    action = str(args.get("action", "pe_symbols")).strip()
    query = str(args.get("query", ""))
    arch = str(args.get("arch", "x64"))
    count = _clamp_int(args.get("count", 25), default=25, lo=1, hi=500)

    try:
        if action == "disassemble_address":
            offset_val = _parse_int_arg(query)
            res = disassemble_bytes_at(target_path, offset_val, is_va=True, arch=arch, instruction_count=count)
        elif action == "pe_symbols":
            res = inspect_pe_symbols(target_path)
        elif action == "android_class":
            res = inspect_android_class(target_path, query)
        elif action == "pseudo_c":
            res = decompile_function_ghidra(target_path, query)
        elif action == "go_symbols":
            res = inspect_go_binary(target_path)
        elif action == "rust_metadata":
            res = inspect_rust_binary(target_path)
        elif action == "flutter_dart":
            res = inspect_flutter_dart(target_path)
        elif action == "simplify_mba":
            from mba_engine import simplify_mba_expression
            res = simplify_mba_expression(query)
        elif action == "hensel_inverse":
            from mba_engine import hensel_lift_polynomial_inverse
            val = _parse_int_arg(query)
            res = {"target": hex(val), "hensel_root": hex(hensel_lift_polynomial_inverse(val))}
        elif action == "modular_inverse":
            from mba_engine import modular_inverse_64
            val = _parse_int_arg(query)
            res = modular_inverse_64(val)
        elif action == "rebuild_pe":
            from rebuilder_engine import rebuild_pe_file
            new_oep = _parse_int_arg(query)
            p_in = Path(target_path).resolve()
            out_path = str(p_in.with_name(f"{p_in.stem}_unpacked{p_in.suffix or '.exe'}"))
            res = rebuild_pe_file(input_pe=str(p_in), output_pe=out_path, new_oep_va_or_rva=new_oep)
        elif action == "scan_honeypots":
            from rebuilder_engine import scan_anti_dump_honeypots
            res = scan_anti_dump_honeypots(target_path)
        elif action == "read_bytes":
            from triage_engine import read_bytes_at
            offset_val = _parse_int_arg(query, default=0)
            res = read_bytes_at(target_path, offset=offset_val, length=count)
        elif action == "read_rva":
            from triage_engine import read_at_rva
            rva_val = _parse_int_arg(query, default=0)
            res = read_at_rva(target_path, rva=rva_val, length=count)
        elif action == "search_bytes":
            from triage_engine import search_bytes
            is_hex = not query.startswith("str:")
            clean_q = query[4:] if query.startswith("str:") else query
            res = search_bytes(target_path, pattern=clean_q, is_hex=is_hex, max_results=count)
        elif action == "crypto_signatures":
            from triage_engine import detect_crypto
            data = safe_read_binary(target_path)
            res = detect_crypto(data)
        elif action == "indicators":
            from triage_engine import extract_indicators
            data = safe_read_binary(target_path)
            res = extract_indicators(data, max_per_category=count)
        elif action == "capabilities":
            from triage_engine import match_capabilities
            res = {"capabilities": match_capabilities(target_path)}
        elif action == "wasm_disasm":
            from wasm_engine import disassemble_wasm
            res = disassemble_wasm(target_path, max_lines=count)
        elif action == "wasm_headers":
            from wasm_engine import inspect_wasm_headers
            res = inspect_wasm_headers(target_path)
        elif action == "unpack_sourcemap":
            from web_bundle_engine import unpack_sourcemap
            out_d = query if query and os.path.isabs(query) else None
            res = unpack_sourcemap(target_path, extract_to_dir=out_d)
        elif action == "analyze_web_bundle":
            from web_bundle_engine import analyze_web_bundle
            res = analyze_web_bundle(target_path)
        elif action == "android_xref":
            from android_ext_engine import trace_android_references
            res = trace_android_references(target_path, query=query, max_results=count)
        elif action == "android_resources":
            from android_ext_engine import decode_android_resources
            res = decode_android_resources(target_path, max_strings=count)
        elif action == "pe_lea_xrefs":
            from native_tls_hwbp_engine import scan_pe_lea_xrefs
            res = scan_pe_lea_xrefs(target_path, query_str=query if query else None)
        elif action == "native_crypto_prologues":
            from native_tls_hwbp_engine import scan_native_crypto_prologues
            res = scan_native_crypto_prologues(target_path)
        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    except ValueError as ve:
        return {"isError": True, "content": [{"type": "text", "text": f"Gecersiz parametre degeri: {ve}"}]}
    except FileNotFoundError as fnf:
        return {"isError": True, "content": [{"type": "text", "text": f"Dosya bulunamadi: {fnf}"}]}

    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_dynamic_probe(args: dict[str, Any]) -> dict[str, Any]:
    from live_engine import (
        frida_list_devices, frida_list_processes, frida_inject_script,
        adb_list_devices, adb_shell, adb_pull_file, adb_read_logcat
    )
    action = str(args.get("action", "frida_devices")).strip()
    target = args.get("target")
    payload = str(args.get("payload", "") or "")
    device_id = str(args.get("device_id") or "").strip() or None
    try:
        raw_timeout = float(args.get("timeout", 5.0))
    except Exception:
        raw_timeout = 5.0
    timeout = max(0.2, min(30.0, raw_timeout))

    if action == "unicorn_emulate":
        from emulator_engine import emulate_pe_range
        if not target:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target' (PE dosya yolu) zorunludur."}]}

        start_va = 0x140001000
        end_va = 0x140005000
        if payload and ":" in payload:
            parts = payload.split(":", 1)
            try:
                start_va = _parse_int_arg(parts[0])
                end_va = _parse_int_arg(parts[1])
            except ValueError as ve:
                return {"isError": True, "content": [{"type": "text", "text": f"Gecersiz VA araligi: {ve}"}]}
        max_insn = max(10, min(50000, int(timeout * 2000)))
        res = emulate_pe_range(pe_path=str(target), start_va=start_va, end_va=end_va, max_instructions=max_insn)
    elif action == "frida_devices":
        res = frida_list_devices()
    elif action == "frida_processes":
        res = frida_list_processes(device_id=device_id or (str(target) if target else "local"))
    elif action == "frida_inject":
        if not target or not payload:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target' (PID/surec adi) ve 'payload' (Frida JS kodu) zorunludur."}]}
        res = frida_inject_script(target=target, script_source=payload, device_id=device_id or "local", timeout_sec=timeout)
    elif action == "adb_devices":
        res = adb_list_devices()
    elif action == "adb_shell":
        if not payload:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'payload' (shell komutu) zorunludur."}]}
        res = adb_shell(payload, device_id=device_id or (str(target) if target else None))
    elif action == "adb_pull":
        if not payload or not target:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target' (uzak cihaz yolu) ve 'payload' (yerel hedef yolu) zorunludur."}]}
        res = adb_pull_file(remote_path=str(target), local_path=str(payload), device_id=device_id)
    elif action == "adb_logcat":
        lines_cnt = _clamp_int(target, default=50, lo=1, hi=500) if str(target or "").isdigit() else 50
        res = adb_read_logcat(filter_pattern=payload if payload else None, lines=lines_cnt, device_id=device_id)
    elif action in ("memory_dump", "dynamic_unpack"):
        if not target:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target' (PE dosya yolu) zorunludur."}]}
        from dynamic_unpacker import run_dynamic_memory_unpack
        res = run_dynamic_memory_unpack(pe_path=str(target), wait_time_sec=min(10.0, timeout), feed_input=payload)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}

    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_session(args: dict[str, Any]) -> dict[str, Any]:
    from session_engine import BinarySession
    action = args.get("action", "list")
    target_path = args.get("target_path", "")
    session_id = args.get("session_id", "")
    ann_type = args.get("annotation_type", "bookmark")
    address = args.get("address", "")
    value = args.get("value", "")

    if action == "open":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = BinarySession.open_session(target_path)
    elif action == "annotate":
        if not session_id or not address or not value:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'session_id', 'address' ve 'value' zorunludur."}]}
        res = BinarySession.annotate(session_id, ann_type, address, value)
    elif action == "get":
        if not session_id:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'session_id' zorunludur."}]}
        res = BinarySession.get_session(session_id)
    elif action == "list":
        res = BinarySession.list_sessions()
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}

    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_native_tls_tracer(args: dict[str, Any]) -> dict[str, Any]:
    from native_tls_hwbp_engine import (
        audit_pe_auth_tls,
        scan_pe_lea_xrefs,
        scan_native_crypto_prologues,
        scan_verify_detached_4stage,
        audit_iat_and_integrity_surface,
        ed25519_rfc8032_self_test,
        export_native_tls_hwbp_tracer,
    )
    action = args.get("action", "audit_target")
    target_path = args.get("target_path", "")
    query = args.get("query", "")

    if action == "audit_target":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = audit_pe_auth_tls(target_path)
    elif action == "scan_lea_xrefs":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = scan_pe_lea_xrefs(target_path, query_str=query if query else None)
    elif action == "scan_crypto_prologues":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = scan_native_crypto_prologues(target_path)
    elif action == "scan_verify_4stage":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = scan_verify_detached_4stage(target_path)
    elif action == "audit_iat_integrity":
        if not target_path:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'target_path' zorunludur."}]}
        res = audit_iat_and_integrity_surface(target_path)
    elif action == "ed25519_self_test":
        res = ed25519_rfc8032_self_test()
    elif action == "export_tracer_sdk":
        res = export_native_tls_hwbp_tracer(output_dir=target_path if target_path else None)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}

    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_advanced_native(args: dict[str, Any]) -> dict[str, Any]:
    from native_packer_engine import (
        bindiff_binaries,
        inspect_dotnet_cil,
        reconstruct_iat_scylla,
        scan_direct_syscalls,
        synthesize_yara_and_crypto,
    )
    action = str(args.get("action", "")).strip()
    target_path = str(args.get("target_path", "")).strip()
    secondary = str(args.get("secondary_path", "") or "").strip() or None

    if action == "dotnet_cil":
        res = inspect_dotnet_cil(target_path, extract_costura_dir=secondary)
    elif action == "iat_scylla":
        res = reconstruct_iat_scylla(target_path)
    elif action == "direct_syscalls":
        res = scan_direct_syscalls(target_path)
    elif action == "yara_crypto":
        res = synthesize_yara_and_crypto(target_path, rule_name=secondary)
    elif action == "bindiff":
        if not secondary:
            return {"isError": True, "content": [{"type": "text", "text": "Hata: 'bindiff' icin 'secondary_path' zorunludur."}]}
        res = bindiff_binaries(target_path, secondary)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_mobile_deep(args: dict[str, Any]) -> dict[str, Any]:
    from mobile_deep_engine import (
        analyze_flutter_aot_snapshot,
        analyze_ios_ipa_macho,
        decompile_hermes_bytecode,
        dump_unity_il2cpp,
        generate_frida_bypass_bundle,
    )
    action = str(args.get("action", "")).strip()
    target_path = str(args.get("target_path", "") or "").strip()
    extra = str(args.get("profile_or_meta", "") or "").strip() or None

    if action == "flutter_aot":
        res = analyze_flutter_aot_snapshot(target_path)
    elif action == "hermes_hbc":
        res = decompile_hermes_bytecode(target_path)
    elif action == "unity_il2cpp":
        res = dump_unity_il2cpp(target_path, metadata_path=extra)
    elif action == "ios_ipa_macho":
        res = analyze_ios_ipa_macho(target_path)
    elif action == "frida_bypass":
        res = generate_frida_bypass_bundle(profile=extra or "all", package_name=target_path)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_modern_unpacker(args: dict[str, Any]) -> dict[str, Any]:
    from modern_packers_engine import extract_node_bun_sea, unpack_electron_asar, unpack_python_frozen
    action = str(args.get("action", "")).strip()
    target_path = str(args.get("target_path", "")).strip()
    extract_dir = str(args.get("extract_dir", "") or "").strip() or None

    if action == "electron_asar":
        res = unpack_electron_asar(target_path, extract_dir=extract_dir)
    elif action == "python_frozen":
        res = unpack_python_frozen(target_path, extract_dir=extract_dir)
    elif action == "node_bun_sea":
        res = extract_node_bun_sea(target_path, extract_dir=extract_dir)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_symbolic_protocol(args: dict[str, Any]) -> dict[str, Any]:
    from symbolic_protocol_engine import (
        recover_protobuf_schemas,
        solve_keygen_constraints,
        synthesize_python_client,
        unflatten_ollvm_cfg,
    )
    action = str(args.get("action", "")).strip()
    target_or_expr = str(args.get("target_or_expr", "")).strip()
    extra = str(args.get("extra", "") or "").strip()
    key_len = _clamp_int(args.get("key_length", 16), default=16, lo=1, hi=64)

    if action == "z3_keygen":
        res = solve_keygen_constraints(target_or_expr, key_length=key_len, prefix=extra)
    elif action == "ollvm_unflatten":
        off = _parse_int_arg(extra, default=0)
        res = unflatten_ollvm_cfg(target_or_expr, offset_or_va=off)
    elif action == "generate_client":
        method = extra if extra.upper() in ("GET", "POST", "PUT", "DELETE") else "POST"
        out_p = extra if (extra and extra.upper() not in ("GET", "POST", "PUT", "DELETE")) else None
        res = synthesize_python_client(target_or_expr, method=method, output_path=out_p)
    elif action == "protobuf_recover":
        res = recover_protobuf_schemas(target_or_expr)
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_patch_cfg_memory(args: dict[str, Any]) -> dict[str, Any]:
    from visual_patch_memory_engine import build_visual_cfg, hex_view_and_patch, live_memory_scanner
    action = str(args.get("action", "")).strip()
    target = str(args.get("target", "")).strip()
    addr_raw = str(args.get("address_or_offset", "") or "").strip()
    patch_or_val = str(args.get("patch_or_value", "") or "")
    scan_type = str(args.get("scan_type", "ascii") or "ascii")

    try:
        if action == "hex_view":
            off = _parse_int_arg(addr_raw, default=0)
            res = hex_view_and_patch(target, offset_or_va=off, patch_spec="")
        elif action == "binary_patch":
            off = _parse_int_arg(addr_raw, default=0)
            res = hex_view_and_patch(target, offset_or_va=off, patch_spec=patch_or_val)
        elif action == "visual_cfg":
            off = _parse_int_arg(addr_raw, default=0)
            res = build_visual_cfg(target, offset_or_va=off)
        elif action == "memory_scan":
            pid = _parse_int_arg(target)
            res = live_memory_scanner(pid=pid, scan_type=scan_type, value=patch_or_val)
        elif action == "pointer_scan":
            pid = _parse_int_arg(target)
            ptr_va = _parse_int_arg(addr_raw)
            res = live_memory_scanner(pid=pid, pointer_target_va=ptr_va)
        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen action: {action}"}]}
    except ValueError as ve:
        return {"isError": True, "content": [{"type": "text", "text": f"Gecersiz parametre: {ve}"}]}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_bsim_vault(args: dict[str, Any]) -> dict[str, Any]:
    from mcp_extensions_engine import bsim_vault_action

    res = bsim_vault_action(
        action=str(args.get("action", "match_functions")),
        target_path=str(args.get("target_path", "")),
        query_or_label_prefix=str(args.get("query_or_label_prefix", "")),
    )
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_export_annotations(args: dict[str, Any]) -> dict[str, Any]:
    from mcp_extensions_engine import export_annotations_script

    res = export_annotations_script(
        session_or_target=str(args.get("session_or_target", "")),
        export_format=str(args.get("export_format", "idapython")),
        output_path=str(args.get("output_path", "")).strip() or None,
    )
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_pdb_traffic_correlate(args: dict[str, Any]) -> dict[str, Any]:
    from mcp_extensions_engine import pdb_and_traffic_correlate

    res = pdb_and_traffic_correlate(
        action=str(args.get("action", "pdb_info")),
        target_path=str(args.get("target_path", "")),
    )
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _handle_auto_orchestrate(args: dict[str, Any]) -> dict[str, Any]:
    from mcp_extensions_engine import auto_orchestrate_target

    res = auto_orchestrate_target(str(args.get("target_path", "")))
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


_PROMPTS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "crackme-solve",
        "description": "End-to-end license/serial check reversal using Scylla IAT, Visual CFG, OLLVM CFF unflattening, and Z3 keygen synthesis.",
        "arguments": [{"name": "target_path", "description": "Binary path", "required": True}],
    },
    {
        "name": "apk-deep-audit",
        "description": "Full mobile APK/IPA audit across Manifest, ARSC, DEX secrets, Flutter/Hermes/IL2CPP, and Frida SSL-Pinning bypass generation.",
        "arguments": [{"name": "target_path", "description": "APK or IPA path", "required": True}],
    },
    {
        "name": "electron-unpack-audit",
        "description": "Unpack Electron app.asar or Python/Bun standalone executable and scan recovered JS/Python bundles for endpoints & vulnerabilities.",
        "arguments": [{"name": "target_path", "description": "Packaged archive or executable", "required": True}],
    },
]


def _list_mcp_resources() -> list[dict[str, Any]]:
    from session_engine import BinarySession

    resources = [
        {"uri": "omni://engines/catalog", "name": "OmniReverse v3.2 Engine Catalog (42 Engines / 17 Tools)", "mimeType": "application/json"},
        {"uri": "omni://sessions", "name": "Active Stateful Binary Analysis Sessions", "mimeType": "application/json"},
        {"uri": "omni://exports", "name": "Exported Unpacked Archives, Patched Binaries & IDA/Ghidra Scripts", "mimeType": "application/json"},
    ]
    for sess in BinarySession.list_sessions()[:30]:
        sid = sess.get("session_id", "")
        if sid:
            resources.append({
                "uri": f"omni://sessions/{sid}",
                "name": f"Session {sid} ({sess.get('target_name', 'binary')})",
                "mimeType": "application/json",
            })
    return resources


def _read_mcp_resource(uri: str) -> dict[str, Any]:
    from session_engine import BinarySession

    u = (uri or "").strip()
    if u == "omni://engines/catalog":
        payload = {"server": SERVER_NAME, "version": SERVER_VERSION, "tools_count": len(TOOLS_SCHEMA), "tools": [t["name"] for t in TOOLS_SCHEMA]}
    elif u == "omni://sessions":
        payload = {"sessions": BinarySession.list_sessions()}
    elif u.startswith("omni://sessions/"):
        sid = u.split("omni://sessions/", 1)[1]
        payload = BinarySession.get_session(sid)
    elif u == "omni://exports":
        exp_dir = HERE / ".exports"
        files = [str(p.relative_to(exp_dir)) for p in exp_dir.rglob("*") if p.is_file()][:100] if exp_dir.is_dir() else []
        payload = {"exports_root": str(exp_dir), "files": files}
    else:
        payload = {"error": f"Bilinmeyen kaynak URI: {u}"}
    return {"contents": [{"uri": u, "mimeType": "application/json", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}


_TOOL_DISPATCH = {
    "omni_deep_reverse": _handle_deep_reverse,
    "omni_deobfuscate_snippet": _handle_deobfuscate_snippet,
    "omni_triage_target": _handle_triage_target,
    "omni_audit_sqli": _handle_audit_sqli,
    "omni_inspect_symbol": _handle_inspect_symbol,
    "omni_dynamic_probe": _handle_dynamic_probe,
    "omni_session": _handle_session,
    "omni_native_tls_tracer": _handle_native_tls_tracer,
    "omni_advanced_native": _handle_advanced_native,
    "omni_mobile_deep": _handle_mobile_deep,
    "omni_modern_unpacker": _handle_modern_unpacker,
    "omni_symbolic_protocol": _handle_symbolic_protocol,
    "omni_patch_cfg_memory": _handle_patch_cfg_memory,
    "omni_bsim_vault": _handle_bsim_vault,
    "omni_export_annotations": _handle_export_annotations,
    "omni_pdb_traffic_correlate": _handle_pdb_traffic_correlate,
    "omni_auto_orchestrate": _handle_auto_orchestrate,
}


_LAST_MTIME: float = os.path.getmtime(__file__) if os.path.isfile(__file__) else 0.0


async def _handle_tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    global _LAST_MTIME
    handler = _TOOL_DISPATCH.get(name)
    cur_mtime = os.path.getmtime(__file__) if os.path.isfile(__file__) else 0.0
    if (handler is None or cur_mtime > _LAST_MTIME) and os.path.isfile(__file__):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_omni_hot", __file__)
            if spec and spec.loader:
                hot_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(hot_mod)
                _TOOL_DISPATCH.update(getattr(hot_mod, "_TOOL_DISPATCH", {}))
                _LAST_MTIME = cur_mtime
                handler = _TOOL_DISPATCH.get(name)
        except Exception as reload_err:
            _log(f"Hot-reload warning: {reload_err}")
    if handler is None:
        return {"isError": True, "content": [{"type": "text", "text": f"Bilinmeyen arac: '{name}'"}]}
    return await asyncio.to_thread(handler, args)


async def _process_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    if method == "notifications/initialized":
        _log("Client initialized successfully.")
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "resources/list":
        res_list = await asyncio.to_thread(_list_mcp_resources)
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": res_list}}

    if method == "resources/read":
        res_content = await asyncio.to_thread(_read_mcp_resource, str(params.get("uri", "")))
        return {"jsonrpc": "2.0", "id": msg_id, "result": res_content}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": _PROMPTS_SCHEMA}}

    if method == "prompts/get":
        pname = str(params.get("name", ""))
        pargs = params.get("arguments") or {}
        tpath = pargs.get("target_path", "<HEDEF_DOSYA>")
        workflow_txt = (
            f"Hedef '{tpath}' icin '{pname}' tersine muhendislik is akisini calistir:\n"
            f"1. omni_auto_orchestrate(target_path={tpath!r})\n"
            f"2. omni_session(action='open', target_path={tpath!r})\n"
            f"3. Hedef turune gore omni_advanced_native / omni_mobile_deep / omni_modern_unpacker / omni_symbolic_protocol cagir."
        )
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "description": f"OmniReverse workflow: {pname}",
                "messages": [{"role": "user", "content": {"type": "text", "text": workflow_txt}}],
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS_SCHEMA},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        try:
            result = await _handle_tool_call(tool_name, tool_args)
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": str(e)}}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if msg_id is not None:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method '{method}' not found"}}
    return None


async def run_mcp_loop() -> int:
    if sys.platform == "win32":
        try:
            sys.stdin.reconfigure(encoding="utf-8")
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    _log(f"{SERVER_NAME} v{SERVER_VERSION} started on stdio.")

    while True:
        line_str = await asyncio.to_thread(sys.stdin.readline)
        if not line_str:
            break
        if len(line_str) > 4_194_304:
            _log("Rejected oversized JSON-RPC message (>4 MB).")
            continue
        line_str = line_str.strip()
        if not line_str:
            continue

        try:
            msg = json.loads(line_str)
        except json.JSONDecodeError as err:
            _log(f"JSON decode error: {err}")
            continue

        resp = await _process_message(msg)
        if resp is not None:
            raw_out = json.dumps(resp, ensure_ascii=False) + "\n"
            sys.stdout.write(raw_out)
            sys.stdout.flush()

    _log("Shutting down MCP server.")
    return 0


def _get_target_config_paths() -> dict[str, list[Path]]:
    user_home = Path.home()
    appdata = Path(os.environ.get("APPDATA", "")) if os.environ.get("APPDATA") else user_home / "AppData" / "Roaming"

    paths: dict[str, list[Path]] = {
        "claude": [
            appdata / "Claude" / "claude_desktop_config.json",
            user_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            user_home / ".config" / "Claude" / "claude_desktop_config.json",
        ],
        "cursor": [
            user_home / ".cursor" / "mcp.json",
            appdata / "Cursor" / "mcp.json",
        ],
        "antigravity": [
            user_home / ".gemini" / "antigravity" / "mcp_config.json",
            user_home / ".gemini" / "config" / "mcp_servers.json",
        ],
    }
    return paths


def install_mcp_target(target_name: str) -> bool:
    all_targets = _get_target_config_paths()
    script_path = str((HERE / "omni_server.py").resolve())
    python_exe = sys.executable

    targets_to_run = all_targets.keys() if target_name == "all" else [target_name]
    installed_count = 0

    for tgt in targets_to_run:
        candidates = all_targets.get(tgt, [])
        installed_for_tgt = False
        for cfg_path in candidates:
            try:
                cfg_path.parent.mkdir(parents=True, exist_ok=True)
                data: dict[str, Any] = {}
                if cfg_path.is_file():
                    try:
                        data = json.loads(cfg_path.read_text(encoding="utf-8"))
                    except Exception:
                        data = {}
                if "mcpServers" not in data or not isinstance(data["mcpServers"], dict):
                    data["mcpServers"] = {}

                data["mcpServers"]["omni-reverse"] = {
                    "command": python_exe,
                    "args": [script_path],
                }

                cfg_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                print(f"[+] OmniReverse MCP server successfully registered in {tgt.title()} -> {cfg_path}")
                installed_for_tgt = True
                installed_count += 1
                break
            except Exception as e:
                continue

        if not installed_for_tgt and target_name != "all":
            # If default file wasn't created, write to first candidate
            primary = candidates[0]
            try:
                primary.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "mcpServers": {
                        "omni-reverse": {
                            "command": python_exe,
                            "args": [script_path],
                        }
                    }
                }
                primary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                print(f"[+] Created new config & registered OmniReverse in {tgt.title()} -> {primary}")
                installed_count += 1
            except Exception as e:
                print(f"[!] Failed to install for {tgt}: {e}")

    return installed_count > 0


def main() -> int:
    args = sys.argv[1:]
    if "--install-claude" in args:
        install_mcp_target("claude")
        return 0
    if "--install-cursor" in args:
        install_mcp_target("cursor")
        return 0
    if "--install-antigravity" in args:
        install_mcp_target("antigravity")
        return 0
    if "--install-all" in args:
        install_mcp_target("all")
        return 0

    try:
        return asyncio.run(run_mcp_loop())
    except (KeyboardInterrupt, SystemExit):
        return 0


if __name__ == "__main__":
    sys.exit(main())
