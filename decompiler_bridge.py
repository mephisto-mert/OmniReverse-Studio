# -*- coding: utf-8 -*-
"""OmniReverse Decompiler Bridge (decompiler_bridge.py)
Bridges Ghidra headless decompiler across Windows, macOS, and Linux with
CWE-78 BatBadBut command-injection protection and isolated temporary project cleanup.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, get_ghidra_analyzer

SCRIPTS_DIR = STUDIO_ROOT / "scripts"
_FUNC_QUERY_RE = re.compile(r"^[A-Za-z0-9_:@.?$]{0,128}$")
_CMD_META_RE = re.compile(r'[&|<>^%!"\r\n]')


def decompile_function_ghidra(target_path: str, function_query: str = "") -> dict[str, Any]:
    """Invokes Ghidra headless safely to decompile a specific function to C pseudo-code."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Hedef dosya bulunamadi: {target_path}"}

    clean_query = (function_query or "").strip()
    if clean_query.startswith("-") or not _FUNC_QUERY_RE.fullmatch(clean_query):
        return {"error": f"Gecersiz fonksiyon sorgusu formati: {function_query!r}"}

    abs_target = os.path.abspath(target_path)
    if sys.platform == "win32" and _CMD_META_RE.search(abs_target):
        return {"error": "Dosya yolunda guvensiz kabuk metakarakterleri tespit edildi."}

    analyzer_bin = get_ghidra_analyzer()
    if analyzer_bin is None or not analyzer_bin.is_file():
        return {
            "error": (
                "Ghidra analyzeHeadless araci bulunamadi. "
                "OMNI_GHIDRA_DIR ortam degiskenini ayarlayin veya Ghidra'yi PATH'e ekleyin."
            )
        }

    with tempfile.TemporaryDirectory(prefix="omni_ghidra_") as tmp_proj_dir:
        out_c_path = os.path.join(tmp_proj_dir, "decompiled_out.c")
        proj_name = "OmniIsolatedProj"
        cmd = [
            str(analyzer_bin),
            tmp_proj_dir,
            proj_name,
            "-import",
            abs_target,
            "-overwrite",
            "-scriptPath",
            str(SCRIPTS_DIR),
            "-postScript",
            "ExportDecompiledFunction.java",
            clean_query,
            out_c_path,
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

            if os.path.isfile(out_c_path) and os.path.getsize(out_c_path) > 0:
                with open(out_c_path, "r", encoding="utf-8", errors="replace") as f:
                    decompiled_code = f.read(64_000)
                return {
                    "status": "success",
                    "target": os.path.basename(target_path),
                    "query": clean_query,
                    "pseudo_c": decompiled_code[:30000],
                }
            return {
                "status": "error",
                "message": "Ghidra decompile ciktisi olusturulamadi.",
                "stdout_tail": (res.stdout or "")[-1500:],
                "stderr_tail": (res.stderr or "")[-1000:],
            }
        except subprocess.TimeoutExpired:
            return {"error": "Ghidra headless analizi zaman asimina ugradi (120s)."}
        except Exception as e:
            return {"error": f"Ghidra bridge calisma hatasi: {str(e)}"}
