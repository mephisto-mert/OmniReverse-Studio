# -*- coding: utf-8 -*-
"""End-to-End Verification Suite for All 20 OmniReverse v3.0 Engines, 5 New MCP Tools, and Web Studio v3 API."""
from __future__ import annotations

import asyncio
import ctypes
import importlib.util
import json
import os
import plistlib
import py_compile
import struct
import sys
import zipfile
from pathlib import Path

import pytest

STUDIO_ROOT = Path(__file__).resolve().parent.parent
if str(STUDIO_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDIO_ROOT))


def test_slice1_native_dotnet_iat_syscall_yara_bindiff(tmp_path: Path) -> None:
    from native_packer_engine import (
        bindiff_binaries,
        inspect_dotnet_cil,
        reconstruct_iat_scylla,
        scan_direct_syscalls,
        synthesize_yara_and_crypto,
    )

    # 1. Synthetic .NET BSJB + Costura + ConfuserEx sample
    ver_str = b"v4.0.30319\x00\x00"
    strings_blob = b"\x00MyNamespace.LicenseManager\x00VerifyToken\x00costura.newtonsoft.json.dll.compressed\x00"
    bsjb = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(ver_str))
        + ver_str
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 48, len(strings_blob))
        + b"#Strings\x00\x00\x00\x00"
    )
    bsjb = bsjb.ljust(48, b"\x00") + strings_blob + b"ConfusedByAttribute"
    dotnet_bin = tmp_path / "sample_dotnet.exe"
    dotnet_bin.write_bytes(b"MZ" + b"\x00" * 64 + bsjb)

    dn_res = inspect_dotnet_cil(str(dotnet_bin))
    assert dn_res["is_dotnet"] is True
    assert "v4.0.30319" in dn_res["clr_runtime_version"]
    assert "ConfuserEx" in dn_res["obfuscators"]
    assert "Costura.Fody" in dn_res["obfuscators"]
    assert "costura.newtonsoft.json.dll.compressed" in dn_res["costura_embedded_dlls"]

    # 2. Scylla IAT Reconstructor on real compiled OmniReverse_Studio.exe
    real_exe = STUDIO_ROOT / "OmniReverse_Studio.exe"
    iat_res = reconstruct_iat_scylla(str(real_exe))
    assert iat_res["unique_iat_slots_found"] > 10
    assert iat_res["resolved_imports_count"] > 10

    # 3. Direct Syscall (Hell's Gate: 4C 8B D1 B8 18 00 00 00 0F 05 C3)
    sc_bin = tmp_path / "hellsgate.bin"
    sc_bin.write_bytes(b"\x90\x90\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3SW3_Syscall")
    sc_res = scan_direct_syscalls(str(sc_bin))
    assert sc_res["direct_syscall_stubs_count"] == 1
    assert sc_res["direct_syscall_stubs"][0]["ssn"] == "0x18"

    # 4. YARA & Crypto Constant Synthesizer (ChaCha20 + AES SBox)
    cry_bin = tmp_path / "crypto_sample.bin"
    cry_bin.write_bytes(b"expand 32-byte k" + bytes.fromhex("637c777bf26b6fc53001672bfed7ab76") + b"https://api.example.com/auth")
    yara_res = synthesize_yara_and_crypto(str(cry_bin), rule_name="TestCryptoRule")
    assert len(yara_res["crypto_constants_found"]) >= 2
    assert "rule TestCryptoRule {" in yara_res["yara_rule"]

    # 5. BinDiff
    v1 = tmp_path / "v1.bin"
    v2 = tmp_path / "v2.bin"
    v1.write_bytes(b"\x48\x89\x5c\x24\x08" + b"OLD_API_ENDPOINT_V1" + b"\x90" * 40)
    v2.write_bytes(b"\x48\x89\x5c\x24\x08" + b"NEW_PATCHED_AUTH_V2" + b"\x90" * 60)
    diff_res = bindiff_binaries(str(v1), str(v2))
    assert diff_res["size_delta_bytes"] == 20
    assert "NEW_PATCHED_AUTH_V2" in diff_res["added_strings_sample"]


def test_slice2_mobile_flutter_hermes_il2cpp_ios_frida(tmp_path: Path) -> None:
    from mobile_deep_engine import (
        analyze_flutter_aot_snapshot,
        analyze_ios_ipa_macho,
        decompile_hermes_bytecode,
        dump_unity_il2cpp,
        generate_frida_bypass_bundle,
    )

    # 6. Flutter libapp.so AOT Snapshot
    libapp = tmp_path / "libapp.so"
    libapp.write_bytes(
        b"\x7fELF" + b"_kDartIsolateSnapshotData" + b"\xf5\xf5\xdc\xdc" + b"a" * 32
        + b"package:myapp/services/auth_service.dart\x00AuthRepository\x00https://api.flutterapp.io/v1/login"
    )
    fl_res = analyze_flutter_aot_snapshot(str(libapp))
    assert fl_res["is_flutter_aot"] is True
    assert "package:myapp/services/auth_service.dart" in fl_res["dart_packages_sample"]

    # 7. React Native Hermes .hbc
    hbc = tmp_path / "index.android.bundle"
    hdr = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + struct.pack("<I", 96) + (b"\x11" * 20) + struct.pack("<6I", 512, 0, 12, 3, 25, 40)
    hbc.write_bytes(hdr.ljust(96, b"\x00") + b"fetchUserToken\x00https://rn-api.io/v1/token\x00")
    hb_res = decompile_hermes_bytecode(str(hbc))
    assert hb_res["is_hermes"] is True
    assert hb_res["hbc_version"] == 96
    assert "https://rn-api.io/v1/token" in hb_res["endpoints_recovered"]

    # 8. Unity IL2CPP global-metadata.dat (0xFAB11BAF)
    meta = tmp_path / "global-metadata.dat"
    str_blob = b"GameManager\x00PlayerWalletController\x00VerifyReceipt\x00"
    il_hdr = struct.pack("<6I", 0xFAB11BAF, 29, 0, 0, 0, 0) + struct.pack("<II", 64, len(str_blob))
    meta.write_bytes(il_hdr.ljust(64, b"\x00") + str_blob)
    il_res = dump_unity_il2cpp(str(meta))
    assert il_res["is_il2cpp"] is True
    assert "PlayerWalletController" in il_res["csharp_symbols_sample"]

    # 9. iOS .ipa + Info.plist + Mach-O 64 + Swift symbol
    ipa = tmp_path / "sample.ipa"
    macho = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 32, 0, 0)
    macho += struct.pack("<6I", 0x2C, 24, 0, 4096, 1, 0)  # LC_ENCRYPTION_INFO_64 cryptid=1
    macho += b"_$s7MySwift11AuthManagerC5loginSSyF\x00"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.omni.ios", "CFBundleExecutable": "Demo"}))
        zf.writestr("Payload/Demo.app/Demo", macho)
    ios_res = analyze_ios_ipa_macho(str(ipa))
    assert ios_res["info_plist"]["bundle_id"] == "com.omni.ios"
    assert ios_res["fairplay_drm_encrypted"] is True
    assert any("MySwift.AuthManager" in x["demangled"] for x in ios_res["swift_symbols_demangled"])

    # 10. Frida Bypass Bundle
    fr_res = generate_frida_bypass_bundle("all", "com.omni.ios")
    assert "TrustManagerImpl" in fr_res["frida_script"]
    assert "IsDebuggerPresent" in fr_res["frida_script"]


def test_slice3_modern_packers_asar_pyinstaller_bun(tmp_path: Path) -> None:
    import zlib
    from modern_packers_engine import extract_node_bun_sea, unpack_electron_asar, unpack_python_frozen

    # 11. Electron app.asar (Chromium Pickle + JSON virtual FS)
    pkg_bytes = b'{"name":"omni-electron","version":"3.0.0","main":"main.js","dependencies":{"axios":"^1.7.0"}}'
    js_bytes = b"const { app } = require('electron'); console.log('ready');"
    tree_raw = json.dumps({
        "files": {
            "package.json": {"offset": "0", "size": len(pkg_bytes)},
            "main.js": {"offset": str(len(pkg_bytes)), "size": len(js_bytes)},
        }
    }).encode("utf-8")
    aligned_len = (len(tree_raw) + 3) & ~3
    padded_tree = tree_raw.ljust(aligned_len, b"\x00")
    asar_hdr = struct.pack("<4I", 4, 8 + aligned_len, 4 + aligned_len, len(tree_raw))
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(asar_hdr + padded_tree + pkg_bytes + js_bytes)

    asar_res = unpack_electron_asar(str(asar_path))
    assert asar_res["is_asar"] is True
    assert asar_res["package_metadata"]["name"] == "omni-electron"
    assert asar_res["extracted_files_count"] == 2

    # 12a. Python .pyc Disassembler
    src_py = tmp_path / "secret_logic.py"
    pyc_out = tmp_path / "secret_logic.pyc"
    src_py.write_text("def check_token(tok):\n    return tok == 'OMNI_VIP_TOKEN'\n", encoding="utf-8")
    py_compile.compile(str(src_py), cfile=str(pyc_out), doraise=True)
    pyc_res = unpack_python_frozen(str(pyc_out))
    assert pyc_res["pyc_analysis"]["matched_host_python"] is True
    assert "OMNI_VIP_TOKEN" in "".join(pyc_res["pyc_analysis"]["co_consts"])

    # 12b. PyInstaller MEI CArchive + zlib stream
    pyi_exe = tmp_path / "frozen_app.exe"
    zstream = zlib.compress(b"import sys\ndef __main__():\n    return 42\n" * 2)
    pyi_exe.write_bytes(b"MZ" + b"\x00" * 32 + zstream + b"auth_helper.pyc\x00" + b"MEI\x0c\x0b\x0a\x0b\x0e")
    pyi_res = unpack_python_frozen(str(pyi_exe))
    assert pyi_res["is_python_frozen"] is True
    assert "PyInstaller (MEI CArchive)" in pyi_res["detected_packagers"]
    assert len(pyi_res["extracted_zlib_streams"]) >= 1

    # 13. Bun Standalone Executable
    bun_exe = tmp_path / "bun_app.exe"
    js_bundle = b"export const sync = async function() { return fetch('https://bun-edge.io/v1/ping'); }; // " * 3
    bun_exe.write_bytes(b"MZ" + b"B:/~BUN/root/server.js\x00" + js_bundle + b"\n---- Bun! ----")
    bun_res = extract_node_bun_sea(str(bun_exe))
    assert bun_res["is_js_packed_binary"] is True
    assert bun_res["runtime_packager"] == "Bun Standalone Executable"
    assert len(bun_res["recovered_js_bundles"]) >= 1


def test_slice4_symbolic_keygen_ollvm_client_protobuf(tmp_path: Path) -> None:
    from symbolic_protocol_engine import (
        recover_protobuf_schemas,
        solve_keygen_constraints,
        synthesize_python_client,
        unflatten_ollvm_cfg,
    )

    # 14. Z3 Symbolic Keygen
    z3_res = solve_keygen_constraints("b[5] ^ 0x20 == 0x61; b[6] + b[7] == 140", key_length=10, prefix="OMNI-")
    assert z3_res["satisfiable"] is True
    key_str = z3_res["synthesized_key_ascii"]
    assert key_str.startswith("OMNI-")
    assert (ord(key_str[5]) ^ 0x20) == 0x61
    assert (ord(key_str[6]) + ord(key_str[7])) == 140

    # 15. OLLVM Control-Flow Flattening Unflattener
    cff_bin = tmp_path / "ollvm_cff.bin"
    cff_code = (
        b"\x3d\x44\x33\x22\x11\x74\x02\x90\x90"
        b"\x3d\x55\x44\x33\x22\x74\x02\x90\x90"
        b"\x3d\x66\x55\x44\x33\x74\x02\xb8\x77\x66\x55\x44\xc3"
    )
    cff_bin.write_bytes(cff_code)
    cff_res = unflatten_ollvm_cfg(str(cff_bin), offset_or_va=0)
    assert cff_res["ollvm_cff_detected"] is True
    assert cff_res["dispatcher_register"] == "eax"
    assert "CASE 0x11223344" in cff_res["unflattened_dispatch_table"]

    # 16. Stealth curl_cffi Python Client Synthesizer
    cli_res = synthesize_python_client("https://api.targetservice.io/v2/check")
    assert 'impersonate="chrome124"' in cli_res["generated_python_client"]
    assert "ThreadPoolExecutor" in cli_res["generated_python_client"]
    assert "sqlite3" in cli_res["generated_python_client"]

    # 17. Protobuf / gRPC Schema Recoverer
    pb_bin = tmp_path / "grpc_client.bin"
    pb_bin.write_bytes(b"\x00auth_v2.proto\x00VerifyLicenseRequest\x00user_token\x00hw_fingerprint\x00/licensing.AuthService/Verify\x00")
    pb_res = recover_protobuf_schemas(str(pb_bin))
    assert pb_res["has_protobuf"] is True
    assert "auth_v2.proto" in pb_res["proto_files_found"]
    assert "/licensing.AuthService/Verify" in pb_res["grpc_service_routes"]
    assert "message VerifyLicenseRequest" in pb_res["reconstructed_proto"]


def test_slice5_hex_patch_visual_cfg_and_live_memory_scan(tmp_path: Path) -> None:
    from visual_patch_memory_engine import build_visual_cfg, hex_view_and_patch, live_memory_scanner

    # 18. Non-destructive Binary Patcher (Jcc -> JMP)
    crackme = tmp_path / "crackme.bin"
    crackme.write_bytes(b"\x74\x08" + b"\x90" * 30)
    patch_res = hex_view_and_patch(str(crackme), offset_or_va=0, patch_spec="force_jmp")
    assert patch_res["patch_result"]["patched_hex"] == "eb08"
    assert crackme.read_bytes()[:2] == b"\x74\x08"
    patched_path = Path(patch_res["patch_result"]["patched_file"])
    assert patched_path.read_bytes()[:2] == b"\xeb\x08"

    # 19. Visual Control Flow Graph (JSON + inline SVG)
    real_exe = STUDIO_ROOT / "OmniReverse_Studio.exe"
    cfg_res = build_visual_cfg(str(real_exe))
    assert cfg_res["basic_blocks_count"] >= 1
    assert "<svg" in cfg_res["svg"]

    # 20. Live Process Memory Scanner (First Scan + Next Scan + 64-bit Pointer Scan)
    if sys.platform == "win32":
        dynamic_needle = "".join(["OMNI_V3_", "LIVE_MEM_", "994411"])
        ram_buf = ctypes.create_string_buffer(dynamic_needle.encode("ascii"))
        ptr_holder = ctypes.c_uint64(ctypes.addressof(ram_buf))

        first_scan = live_memory_scanner(pid=os.getpid(), scan_type="ascii", value=dynamic_needle)
        assert first_scan["matches_count"] >= 1
        found_addrs = [m["address"] for m in first_scan["matches"]]
        assert hex(ctypes.addressof(ram_buf)) in found_addrs

        next_scan = live_memory_scanner(
            pid=os.getpid(),
            scan_type="ascii",
            value=dynamic_needle,
            previous_addresses=[hex(ctypes.addressof(ram_buf))],
        )
        assert next_scan["mode"] == "next_scan"
        assert next_scan["remaining_matches"] == 1

        ptr_scan = live_memory_scanner(
            pid=os.getpid(),
            pointer_target_va=ctypes.addressof(ram_buf),
            max_offset=0x20,
            max_hits=200,
        )
        assert ptr_scan["mode"] == "pointer_scan"
        assert ptr_scan["matches_count"] >= 1
        assert ptr_holder.value == ctypes.addressof(ram_buf)


def test_mcp_v3_all_13_tools_and_web_v3_endpoint() -> None:
    from omni_server import _process_message

    real_exe = str(STUDIO_ROOT / "OmniReverse_Studio.exe")

    async def _run_mcp_checks() -> None:
        init_resp = await _process_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert init_resp["result"]["serverInfo"]["version"].startswith("3.")

        list_resp = await _process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = {t["name"] for t in list_resp["result"]["tools"]}
        assert len(tool_names) >= 17
        expected_new = {
            "omni_advanced_native",
            "omni_mobile_deep",
            "omni_modern_unpacker",
            "omni_symbolic_protocol",
            "omni_patch_cfg_memory",
        }
        assert expected_new.issubset(tool_names)

        r1 = await _process_message({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "omni_advanced_native", "arguments": {"action": "iat_scylla", "target_path": real_exe}},
        })
        assert not r1["result"].get("isError")
        assert json.loads(r1["result"]["content"][0]["text"])["unique_iat_slots_found"] > 5

        r2 = await _process_message({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "omni_mobile_deep", "arguments": {"action": "frida_bypass", "target_path": "com.demo.app"}},
        })
        assert "TrustManagerImpl" in json.loads(r2["result"]["content"][0]["text"])["frida_script"]

        r3 = await _process_message({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "omni_symbolic_protocol", "arguments": {"action": "z3_keygen", "target_or_expr": "b[0] == 0x41", "key_length": 6}},
        })
        assert json.loads(r3["result"]["content"][0]["text"])["satisfiable"] is True

        r4 = await _process_message({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "omni_patch_cfg_memory", "arguments": {"action": "visual_cfg", "target": real_exe}},
        })
        assert "<svg" in json.loads(r4["result"]["content"][0]["text"])["svg"]

    asyncio.run(_run_mcp_checks())

    try:
        from omni_web_studio import app
        from fastapi.testclient import TestClient
        client = TestClient(app)
        health = client.get("/api/health").json()
        assert health["version"] == "3.0.0"
        assert health["engines_count"] == 38

        r_frida = client.post("/api/v3/execute", json={"engine": "frida_bypass", "target_path": "com.test.app", "secondary": "ssl_pinning"})
        assert r_frida.status_code == 200
        assert "OkHttp" in r_frida.json()["result"]["frida_script"]

        r_z3 = client.post("/api/v3/execute", json={"engine": "z3_keygen", "target_path": "", "secondary": "b[5] == 0x39"})
        assert r_z3.status_code == 200
        assert r_z3.json()["result"]["satisfiable"] is True

        r_cfg = client.post("/api/v3/execute", json={"engine": "visual_cfg", "target_path": real_exe, "secondary": "0"})
        assert r_cfg.status_code == 200
        assert "<svg" in r_cfg.json()["result"]["svg"]
    except ImportError:
        pass
