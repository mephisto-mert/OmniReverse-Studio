# -*- coding: utf-8 -*-
"""Pipeline regression test suite (portable replacement for legacy top-level script)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from pipeline import run_pipeline


def test_pipeline_on_compiled_studio_pe() -> None:
    exe_path = HERE / "OmniReverse_Studio.exe"
    assert exe_path.is_file(), "OmniReverse_Studio.exe must exist before pipeline test"
    with tempfile.TemporaryDirectory() as tmpdir:
        rep = run_pipeline(str(exe_path), export_base=tmpdir, allow_live_execution=False)
        assert rep.kind == "pe"
        assert rep.file_size > 10_000
        assert len(rep.sha256) == 64
        md = rep.to_markdown()
        assert "OmniReverse Pipeline Report" in md


def test_pipeline_never_executes_hollowed_pe_by_default() -> None:
    """Verifies CWE-94 fix: packed/VMP/hollowed binary is NEVER launched when allow_live_execution=False."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_vmp = Path(tmpdir) / "packed_sample.exe"
        # Minimal MZ + .vmp marker
        fake_vmp.write_bytes(b"MZ" + b"\x00" * 128 + b".vmp0\x00\x00\x00" + b"CreateFileMappingW\x00")
        rep = run_pipeline(str(fake_vmp), export_base=tmpdir, allow_live_execution=False)
        assert "VMProtect" in rep.obfuscators
        assert any("canlı çalıştırma devre dışı" in line for line in rep.pipeline_log)


if __name__ == "__main__":
    test_pipeline_on_compiled_studio_pe()
    test_pipeline_never_executes_hollowed_pe_by_default()
    print("[+] test_aszs_pipeline passed!")
