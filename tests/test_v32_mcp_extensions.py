# -*- coding: utf-8 -*-
"""End-to-End Verification for OmniReverse MCP v3.2 Extensions (17 Tools, Resources, Prompts) & MCP Auto-Router Skill."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
import struct
import sys
from pathlib import Path

STUDIO_ROOT = Path(__file__).resolve().parent.parent
if str(STUDIO_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDIO_ROOT))


def test_v32_bsim_annotations_pdb_vault_har_and_orchestrator(tmp_path: Path) -> None:
    from mcp_extensions_engine import (
        auto_orchestrate_target,
        bsim_vault_action,
        export_annotations_script,
        pdb_and_traffic_correlate,
    )
    from session_engine import BinarySession

    real_exe = str(STUDIO_ROOT / "OmniReverse_Studio.exe")

    # 1. BSim SQLite FTS5 Vault: index -> match -> search
    idx_res = bsim_vault_action("index_binary", real_exe, "omnistudio")
    assert idx_res["indexed_functions"] >= 1
    match_res = bsim_vault_action("match_functions", real_exe)
    assert match_res["matched_count"] >= 1
    search_res = bsim_vault_action("search_vault", "", "omnistudio")
    assert search_res["vault_total_signatures"] >= 1
    assert len(search_res["matches"]) >= 1

    # 2. Export Annotations (IDAPython, Ghidra, x64dbg)
    sess = BinarySession.open_session(real_exe)
    sid = sess["session_id"]
    BinarySession.annotate(sid, "comment", "0x140001000", "Verified Entry Stub")
    ida_res = export_annotations_script(sid, "idapython")
    assert "ida_name.set_name" in ida_res["script_preview"]
    assert Path(ida_res["exported_file"]).is_file()

    ghidra_res = export_annotations_script(sid, "ghidra")
    assert "createLabel" in ghidra_res["script_preview"]

    x64_res = export_annotations_script(sid, "x64dbg")
    assert Path(x64_res["exported_file"]).name.endswith(".dd64.json")

    # 3. RSDS PDB, DPAPI Vault Header & HAR -> OpenAPI 3.1
    rsds_pe = tmp_path / "with_pdb.exe"
    rsds_blob = b"RSDS" + (b"\x11" * 16) + struct.pack("<I", 2) + b"C:\\build\\app_release.pdb\x00"
    rsds_pe.write_bytes(b"MZ" + b"\x00" * 64 + rsds_blob)
    pdb_res = pdb_and_traffic_correlate("pdb_info", str(rsds_pe))
    assert pdb_res["has_rsds_pdb"] is True
    assert "app_release.pdb" in pdb_res["msdl_symbol_url"]

    dpapi_file = tmp_path / "cred_blob.bin"
    dpapi_file.write_bytes(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xebAndroidKeyStore")
    v_res = pdb_and_traffic_correlate("vault_headers", str(dpapi_file))
    assert len(v_res["vault_indicators"]) >= 2

    har_file = tmp_path / "capture.har"
    har_file.write_text(
        json.dumps({
            "log": {
                "entries": [
                    {"request": {"method": "POST", "url": "https://api.service.io/v1/login"}},
                    {"request": {"method": "GET", "url": "https://api.service.io/v1/profile?id=1"}},
                ]
            }
        }),
        encoding="utf-8",
    )
    oa_res = pdb_and_traffic_correlate("har_to_openapi", str(har_file))
    assert oa_res["endpoints_recovered"] == 2
    assert oa_res["openapi_3_1"]["openapi"] == "3.1.0"

    # 4. Auto Orchestrator on real PE
    orch = auto_orchestrate_target(real_exe)
    assert orch["detected_kind"] == "windows_pe"
    assert "iat_scylla" in orch["steps_executed"]


def test_mcp_v32_protocol_resources_prompts_and_auto_router_skill(tmp_path: Path) -> None:
    from omni_server import _process_message

    async def _verify_protocol() -> None:
        init_r = await _process_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        caps = init_r["result"]["capabilities"]
        assert "tools" in caps and "resources" in caps and "prompts" in caps
        assert init_r["result"]["serverInfo"]["version"] == "3.2.0"

        tools_r = await _process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert len(tools_r["result"]["tools"]) == 17

        res_list = await _process_message({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
        uris = {r["uri"] for r in res_list["result"]["resources"]}
        assert "omni://engines/catalog" in uris

        res_read = await _process_message({
            "jsonrpc": "2.0", "id": 4, "method": "resources/read",
            "params": {"uri": "omni://engines/catalog"},
        })
        cat = json.loads(res_read["result"]["contents"][0]["text"])
        assert cat["tools_count"] == 17

        pr_list = await _process_message({"jsonrpc": "2.0", "id": 5, "method": "prompts/list"})
        assert len(pr_list["result"]["prompts"]) >= 3

        pr_get = await _process_message({
            "jsonrpc": "2.0", "id": 6, "method": "prompts/get",
            "params": {"name": "crackme-solve", "arguments": {"target_path": "crackme.exe"}},
        })
        assert "omni_auto_orchestrate" in pr_get["result"]["messages"][0]["content"]["text"]

    asyncio.run(_verify_protocol())

    # 5. Verify MCP Auto-Router Skill Script across real project & intent scenarios
    router_script = Path.home() / ".gemini" / "config" / "skills" / "mcp-auto-router" / "scripts" / "mcp_project_router.py"
    if not router_script.is_file():
        router_script = STUDIO_ROOT.parent / ".agents" / "skills" / "mcp-auto-router" / "scripts" / "mcp_project_router.py"
    if router_script.is_file():
        spec = importlib.util.spec_from_file_location("mcp_project_router", router_script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        plan_re = mod.route_mcps(str(STUDIO_ROOT), "exe dosyasini tersine muhendislik ile ac ve keygen coz")
        re_servers = [m["server"] for m in plan_re["recommended_mcps"]]
        assert re_servers[0] == "omni-reverse"
        assert "omni_symbolic_protocol" in plan_re["recommended_mcps"][0]["recommended_tools"]

        ui_dir = tmp_path / "ui_sample"
        ui_dir.mkdir(parents=True, exist_ok=True)
        (ui_dir / "index.html").write_text("<html><body><button>Click</button></body></html>")
        plan_ui = mod.route_mcps(str(ui_dir), "arayuz butonlarini tarayicida test et, figma tasarim ve mirofish juri denetimi yap")
        ui_servers = {m["server"] for m in plan_ui["recommended_mcps"]}
        assert {"playwright", "mirofish"}.issubset(ui_servers)
