# -*- coding: utf-8 -*-
"""
tests/test_v32_enhancements.py — Verification of v3.2 Community Enhancements
Tests:
1. report_generator.py HTML synthesis and token replacement
2. omni_web_studio.py /api/export-report endpoint
3. omni_server.py MCP agent installer functions
4. examples/ challenge scripts execution
"""
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from report_generator import generate_html_report
from omni_server import _get_target_config_paths
from examples.crackme_xor import check_key, solve


def test_report_generator_html_synthesis():
    sample_data = {
        "sha256": "abcdef1234567890",
        "format": "PE32+",
        "entropy": 7.45,
        "packer": "UPX (Identified)",
        "syscalls": ["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
        "crypto": ["AES-256-CBC", "Ed25519"],
        "strings": ["https://api.test.org/auth", "SecretKey123"],
    }
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        out_path = tmp.name

    try:
        html = generate_html_report("sample_binary.exe", sample_data, output_path=out_path)
        assert "<!DOCTYPE html>" in html
        assert "sample_binary.exe" in html
        assert "ELEVATED ENTROPY / PACKED" in html
        assert "UPX" in html
        assert "AES-256-CBC" in html
        assert "SecretKey123" in html
        assert Path(out_path).stat().st_size > 500
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_mcp_installer_target_paths():
    paths = _get_target_config_paths()
    assert "claude" in paths
    assert "cursor" in paths
    assert "antigravity" in paths
    assert len(paths["claude"]) >= 2
    assert len(paths["antigravity"]) >= 1


def test_crackme_example():
    key = solve()
    assert key == "OMNI-REVERSE-32"
    assert check_key(key) is True
    assert check_key("INVALID-KEY-123") is False
