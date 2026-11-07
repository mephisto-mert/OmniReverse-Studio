# -*- coding: utf-8 -*-
"""OmniReverse Android Extended Engine (android_ext_engine.py)
Provides Android method/class cross-reference (XRef) tracing and resources.arsc
string extraction with ZipBomb protection and strict input validation.
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path
from typing import Any

from omni_config import safe_read_binary, safe_zip_read


def trace_android_references(apk_or_dex_path: str, query: str, max_results: int = 40) -> dict[str, Any]:
    """Finds cross-references (calls, usages) of a class, method, or string across Android APK/DEX."""
    if not apk_or_dex_path or not os.path.isfile(apk_or_dex_path):
        return {"error": f"APK/DEX dosyasi bulunamadi: {apk_or_dex_path}"}

    clean_query = (query or "").strip()
    if not clean_query:
        return {"error": "XRef aramasi icin gecerli bir sorgu (query) belirtilmelidir."}

    max_results = max(1, min(int(max_results), 200))
    target = Path(apk_or_dex_path)
    matches = []
    q_bytes = clean_query.encode("utf-8", errors="ignore")
    if not q_bytes:
        return {"error": "Arama deseni bos."}

    if zipfile.is_zipfile(target):
        try:
            with zipfile.ZipFile(target, "r") as zf:
                dex_names = [n for n in zf.namelist() if n.endswith(".dex")]
                for dex_n in dex_names[:12]:
                    dex_data = safe_zip_read(zf, dex_n)
                    idx = 0
                    while len(matches) < max_results:
                        pos = dex_data.find(q_bytes, idx)
                        if pos == -1:
                            break
                        ctx_raw = dex_data[max(0, pos - 32) : min(len(dex_data), pos + 64)]
                        readable = "".join(chr(b) if 32 <= b <= 126 else "." for b in ctx_raw)
                        matches.append({
                            "dex_file": dex_n,
                            "offset": hex(pos),
                            "context_preview": readable,
                        })
                        idx = pos + len(q_bytes)
        except Exception as e:
            return {"error": f"APK XRef tarama hatasi: {str(e)}"}
    else:
        try:
            raw_dex = safe_read_binary(target)
            if len(raw_dex) < 8 or not raw_dex.startswith((b"dex\n", b"dey\n")):
                return {"error": "Gecerli bir APK (ZIP) veya DEX dosyasi degil."}
            idx = 0
            while len(matches) < max_results:
                pos = raw_dex.find(q_bytes, idx)
                if pos == -1:
                    break
                ctx_raw = raw_dex[max(0, pos - 32) : min(len(raw_dex), pos + 64)]
                readable = "".join(chr(b) if 32 <= b <= 126 else "." for b in ctx_raw)
                matches.append({
                    "dex_file": target.name,
                    "offset": hex(pos),
                    "context_preview": readable,
                })
                idx = pos + len(q_bytes)
        except Exception as e:
            return {"error": f"DEX XRef tarama hatasi: {str(e)}"}

    return {
        "status": "success",
        "target": target.name,
        "query": clean_query,
        "references_found": len(matches),
        "references": matches,
    }


def decode_android_resources(apk_path: str, max_strings: int = 80) -> dict[str, Any]:
    """Extracts resource files, resources.arsc string pools, and manifest symbols safely."""
    if not apk_path or not os.path.isfile(apk_path):
        return {"error": f"APK dosyasi bulunamadi: {apk_path}"}

    target = Path(apk_path)
    if not zipfile.is_zipfile(target):
        return {"error": "Gecerli bir APK/ZIP dosyasi degil."}

    max_strings = max(1, min(int(max_strings), 500))
    results: dict[str, Any] = {
        "target": target.name,
        "strings_sample": [],
        "manifest_symbols": [],
        "resource_files": [],
    }

    try:
        with zipfile.ZipFile(target, "r") as zf:
            namelist = zf.namelist()
            res_files = [n for n in namelist if n.startswith("res/") or n == "resources.arsc"]
            results["resource_files"] = res_files[:30]

            if "resources.arsc" in namelist:
                arsc_bytes = safe_zip_read(zf, "resources.arsc")
                raw_strings = re.findall(rb"[\x20-\x7e]{4,}", arsc_bytes)
                str_list = [s.decode("latin1", errors="ignore") for s in raw_strings[: max_strings * 2]]
                results["strings_sample"] = list(dict.fromkeys(str_list))[:max_strings]

            if "AndroidManifest.xml" in namelist:
                manifest_raw = safe_zip_read(zf, "AndroidManifest.xml", max_bytes=16 * 1024 * 1024)
                manifest_strings = re.findall(rb"[\x20-\x7e]{3,}", manifest_raw)
                manifest_parsed = [s.decode("latin1", errors="ignore") for s in manifest_strings]
                packages = [s for s in manifest_parsed if "." in s and not s.startswith("http")]
                results["manifest_symbols"] = list(dict.fromkeys(packages))[:25]

        return {"status": "success", "data": results}
    except Exception as e:
        return {"error": f"Resource decode hatasi: {str(e)}"}
