# -*- coding: utf-8 -*-
"""MCP JSON-RPC end-to-end tool protocol tests."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from omni_server import _process_message


async def _run_mcp_suite() -> None:
    r1 = await _process_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r1 is not None
    assert r1["result"]["serverInfo"]["name"] == "omni-reverse"

    r2 = await _process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r2 is not None
    tool_names = [t["name"] for t in r2["result"]["tools"]]
    expected = {
        "omni_deep_reverse",
        "omni_deobfuscate_snippet",
        "omni_triage_target",
        "omni_audit_sqli",
        "omni_inspect_symbol",
        "omni_dynamic_probe",
        "omni_session",
        "omni_native_tls_tracer",
    }
    assert expected.issubset(set(tool_names))

    sample_lua = 'local msg = string.char(79, 109, 110, 105, 82, 101, 118, 101, 114, 115, 101) print(msg)'
    r3 = await _process_message({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "omni_deobfuscate_snippet",
            "arguments": {"code": sample_lua, "language": "lua"},
        },
    })
    assert r3 is not None
    res_json = json.loads(r3["result"]["content"][0]["text"])
    assert "OmniReverse" in res_json["clean_code"]

    with tempfile.TemporaryDirectory() as tmpdir:
        lua_file = Path(tmpdir) / "sample_deobf.lua"
        lua_file.write_text(sample_lua, encoding="utf-8")
        r4 = await _process_message({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "omni_deep_reverse",
                "arguments": {"path": str(lua_file), "format": "markdown"},
            },
        })
        assert r4 is not None
        md_text = r4["result"]["content"][0]["text"]
        assert "OmniReverse Pipeline Report" in md_text
        assert "OmniReverse" in md_text

        r6 = await _process_message({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "omni_native_tls_tracer",
                "arguments": {"action": "export_tracer_sdk", "target_path": str(Path(tmpdir) / "sdk_out")},
            },
        })
        assert r6 is not None
        sdk_info = json.loads(r6["result"]["content"][0]["text"])
        assert sdk_info["status"] == "success"
        assert len(sdk_info["exported_files"]) >= 5

    sqli_snippet = 'cursor.execute(f"SELECT * FROM accounts WHERE id = {acc_id}")'
    r5 = await _process_message({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "omni_audit_sqli",
            "arguments": {"code": sqli_snippet},
        },
    })
    assert r5 is not None
    sqli_report = r5["result"]["content"][0]["text"]
    assert "OmniReverse SAST: SQL Injection" in sqli_report
    assert "CRITICAL" in sqli_report


def test_mcp_protocol_and_core_tools() -> None:
    asyncio.run(_run_mcp_suite())


if __name__ == "__main__":
    test_mcp_protocol_and_core_tools()
    print("[+] ALL OMNI-REVERSE MCP TESTS PASSED!")
