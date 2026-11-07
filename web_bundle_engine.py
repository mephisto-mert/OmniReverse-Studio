# -*- coding: utf-8 -*-
"""OmniReverse Web Bundle & Sourcemap Engine (web_bundle_engine.py)
Reconstructs original TypeScript/JavaScript source trees from minified Webpack, Vite, and Rollup bundles
with strict CWE-22 path-traversal confinement and direct .map file support.
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Any

from omni_config import MAX_TARGET_BYTES, is_safe_subpath, safe_read_binary


def _sanitize_relative_source_path(raw_src: str) -> str:
    """Strips URI schemes, Windows drive letters, root slashes, and '..' segments."""
    s = str(raw_src or "")
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://+", "", s)
    s = s.replace("\\", "/")
    s = re.sub(r"^[a-zA-Z]:/+", "", s)
    parts = []
    for seg in s.split("/"):
        seg = seg.strip()
        if not seg or seg in (".", ".."):
            continue
        seg = re.sub(r'[<>:"|?*\x00-\x1f]', "_", seg)
        parts.append(seg)
    return "/".join(parts) if parts else "recovered_module.js"


def unpack_sourcemap(js_path: str, extract_to_dir: str | None = None) -> dict[str, Any]:
    """Recovers original source code files from a .map file or inline/external JS sourcemap."""
    if not js_path or not os.path.isfile(js_path):
        return {"error": f"JS/Map dosyasi bulunamadi: {js_path}"}

    js_file = Path(js_path).resolve()
    try:
        raw_bytes = safe_read_binary(js_file, max_bytes=min(MAX_TARGET_BYTES, 64 * 1024 * 1024))
        content = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": f"Dosya okunamadi: {str(e)}"}

    map_data: Any = None

    # 0. Direct .map JSON file support
    stripped = content.lstrip()
    if js_file.suffix.lower() == ".map" or (stripped.startswith("{") and '"sources"' in content[:4096]):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict) and ("sources" in parsed or "mappings" in parsed):
                map_data = parsed
        except Exception as e:
            if js_file.suffix.lower() == ".map":
                return {"error": f"Gecersiz JSON sourcemap dosyasi: {str(e)}"}

    # 1. Check for inline base64 sourcemap
    if map_data is None:
        inline_match = re.search(
            r"//#\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)",
            content,
        )
        if inline_match:
            try:
                decoded_json = base64.b64decode(inline_match.group(1)).decode("utf-8", errors="replace")
                map_data = json.loads(decoded_json)
            except Exception as e:
                return {"error": f"Inline sourcemap cozulemedi: {str(e)}"}

    # 2. Check for external .map file strictly inside js_file.parent (CWE-22 guard)
    if map_data is None:
        ext_match = re.search(r"//#\s*sourceMappingURL=([^\s]+)", content)
        if ext_match:
            map_filename = ext_match.group(1).strip()
            if not map_filename.startswith(("http://", "https://", "data:")):
                cand_map = (js_file.parent / map_filename).resolve()
                if is_safe_subpath(cand_map, js_file.parent) and cand_map.is_file():
                    try:
                        raw_map = safe_read_binary(cand_map, max_bytes=64 * 1024 * 1024)
                        map_data = json.loads(raw_map.decode("utf-8", errors="replace"))
                    except Exception as e:
                        return {"error": f"External sourcemap okunamadi: {str(e)}"}

    # 3. Fallback: check if js_path + ".map" exists
    if map_data is None:
        direct_map = Path(str(js_file) + ".map")
        if direct_map.is_file() and is_safe_subpath(direct_map, js_file.parent):
            try:
                raw_map = safe_read_binary(direct_map, max_bytes=64 * 1024 * 1024)
                map_data = json.loads(raw_map.decode("utf-8", errors="replace"))
            except Exception:
                pass

    if not isinstance(map_data, dict):
        return {
            "status": "not_found",
            "message": "Dosyada gecerli bir inline veya iliskili .map sourcemap nesnesi bulunamadi.",
            "target": js_file.name,
        }

    raw_sources = map_data.get("sources")
    raw_contents = map_data.get("sourcesContent")
    sources = raw_sources if isinstance(raw_sources, list) else []
    contents = raw_contents if isinstance(raw_contents, list) else []
    recovered_files = []

    out_dir: Path | None = None
    if extract_to_dir:
        out_dir = Path(extract_to_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

    for idx, src_name in enumerate(sources):
        clean_name = _sanitize_relative_source_path(str(src_name or f"source_{idx}.js"))
        raw_body = contents[idx] if idx < len(contents) else ""
        file_body = str(raw_body) if isinstance(raw_body, str) else ""

        if out_dir is not None:
            target_file_path = (out_dir / clean_name).resolve()
            if is_safe_subpath(target_file_path, out_dir) and target_file_path != out_dir:
                try:
                    target_file_path.parent.mkdir(parents=True, exist_ok=True)
                    target_file_path.write_text(file_body, encoding="utf-8", errors="replace")
                except OSError:
                    pass

        recovered_files.append({
            "path": clean_name,
            "size": len(file_body),
            "preview": file_body[:300] if file_body else "",
        })

    return {
        "status": "success",
        "target": js_file.name,
        "total_sources_recovered": len(recovered_files),
        "export_directory": str(out_dir) if out_dir is not None else None,
        "files_sample": recovered_files[:20],
    }


def analyze_web_bundle(js_path: str) -> dict[str, Any]:
    """Analyzes a JavaScript bundle to detect frameworks, APIs, and module structures."""
    if not js_path or not os.path.isfile(js_path):
        return {"error": f"JS dosyasi bulunamadi: {js_path}"}

    try:
        raw_bytes = safe_read_binary(js_path, max_bytes=min(MAX_TARGET_BYTES, 64 * 1024 * 1024))
        content = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": f"JS okuma hatasi: {str(e)}"}

    frameworks = []
    if "React" in content or "_jsxRuntime" in content:
        frameworks.append("React")
    if "Vue" in content or "__vue_app__" in content:
        frameworks.append("Vue.js")
    if "angular" in content or "ngOnChanges" in content:
        frameworks.append("Angular")
    if "svelte" in content:
        frameworks.append("Svelte")
    if "__NEXT_DATA__" in content or "next/dist" in content:
        frameworks.append("Next.js")

    api_urls = re.findall(
        r"['\"](https?://[a-zA-Z0-9.\-_/:]+|/(?:api|v[0-9]|v1|v2)/[a-zA-Z0-9.\-_/:]+)['\"]",
        content,
    )
    unique_apis = list(dict.fromkeys(api_urls))[:30]

    is_webpack = bool(re.search(r"webpackChunk|__webpack_require__", content))
    is_vite = bool(re.search(r"/@vite/|__vite_plugin__|import\.meta\.env", content))

    return {
        "target": os.path.basename(js_path),
        "bundle_size": len(content),
        "frameworks_detected": frameworks,
        "packer": "Webpack" if is_webpack else ("Vite" if is_vite else "Unknown"),
        "endpoints_found": unique_apis,
    }
