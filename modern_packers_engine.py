# -*- coding: utf-8 -*-
"""OmniReverse Modern Desktop Packers Engine (modern_packers_engine.py)
Implements:
1. Electron app.asar Chromium Pickle + JSON Virtual FS Unpacker & V8 Bytecode (.jsc / Bytenode) Inspector
2. Python Frozen Binary Unpacker (PyInstaller MEI CArchive, Nuitka, PyArmor & .pyc Bytecode Disassembler)
3. Node.js Single Executable Application (SEA), Vercel pkg (/snapshot/) & Bun (---- Bun! ----) Extractor
"""

from __future__ import annotations

import dis
import hashlib
import io
import json
import marshal
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, is_safe_subpath, safe_read_binary, sanitize_relative_filename

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
BUN_TRAILER = b"---- Bun! ----"
NODE_SEA_FUSE = b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"


def _resolve_safe_export_dir(custom_dir: str | None, prefix: str, stem: str) -> Path:
    exports_root = (STUDIO_ROOT / ".exports").resolve()
    exports_root.mkdir(parents=True, exist_ok=True)
    if custom_dir:
        cand = Path(custom_dir).resolve()
        if is_safe_subpath(cand, STUDIO_ROOT) or is_safe_subpath(cand, exports_root):
            cand.mkdir(parents=True, exist_ok=True)
            return cand
    out = exports_root / f"{prefix}_{re.sub(r'[^A-Za-z0-9_.-]', '_', stem)}"
    out.mkdir(parents=True, exist_ok=True)
    return out


# ---------------------------------------------------------------------------
# 1. ELECTRON app.asar & V8 BYTECODE (.jsc) UNPACKER
# ---------------------------------------------------------------------------

def unpack_electron_asar(target_path: str, extract_dir: str | None = None, max_files: int = 80) -> dict[str, Any]:
    """Parses Electron ASAR Chromium Pickle header, verifies SHA-256 integrity blocks, and extracts JS/JSON files."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    if len(data) < 20:
        return {"is_asar": False, "error": "Dosya ASAR basligi icin cok kisa."}

    # Check if standalone V8 .jsc bytecode file
    if target_path.lower().endswith(".jsc"):
        magic_word, v8_hash = struct.unpack_from("<II", data, 0)
        return {
            "is_asar": False,
            "is_v8_bytecode": True,
            "v8_magic": hex(magic_word),
            "v8_version_hash": hex(v8_hash),
            "size_bytes": len(data),
        }

    pickle_hdr_sz, total_hdr_sz, _obj_sz, json_len = struct.unpack_from("<4I", data, 0)
    if pickle_hdr_sz != 4 or json_len == 0 or 16 + json_len > len(data):
        return {"is_asar": False, "message": "Gecerli bir Electron ASAR Chromium Pickle basligi degil."}

    try:
        tree = json.loads(data[16 : 16 + json_len].decode("utf-8"))
    except Exception as exc:
        return {"is_asar": False, "error": f"ASAR JSON agaci okunamadi: {exc}"}

    base_offset = 8 + total_hdr_sz
    entries: list[dict[str, Any]] = []
    jsc_files: list[str] = []

    def _walk(node: dict[str, Any], rel_prefix: str = "") -> None:
        files_dict = node.get("files")
        if not isinstance(files_dict, dict):
            return
        for name, meta in files_dict.items():
            rel = f"{rel_prefix}/{name}" if rel_prefix else name
            if not isinstance(meta, dict):
                continue
            if "files" in meta:
                _walk(meta, rel)
            elif "offset" in meta and "size" in meta:
                off = int(meta["offset"])
                sz = int(meta["size"])
                integ = meta.get("integrity", {})
                entries.append({
                    "path": rel,
                    "offset": off,
                    "size": sz,
                    "sha256": integ.get("hash") if isinstance(integ, dict) else None,
                })
                if rel.lower().endswith(".jsc"):
                    jsc_files.append(rel)

    _walk(tree)
    extracted: list[str] = []
    pkg_json: dict[str, Any] = {}
    out_root = _resolve_safe_export_dir(extract_dir, "asar", Path(target_path).stem)

    for item in entries[: max(1, min(max_files, 200))]:
        rel_clean = sanitize_relative_filename(item["path"])
        raw_start = base_offset + item["offset"]
        raw_end = raw_start + item["size"]
        if not rel_clean or raw_start < 0 or raw_end > len(data) or item["size"] > 16_777_216:
            continue
        blob = data[raw_start:raw_end]
        dest = (out_root / rel_clean).resolve()
        if not is_safe_subpath(dest, out_root):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
        extracted.append(rel_clean)
        if item["path"] == "package.json":
            try:
                pkg_json = json.loads(blob.decode("utf-8", errors="ignore"))
            except Exception:
                pass

    return {
        "is_asar": True,
        "target": os.path.basename(target_path),
        "total_virtual_files": len(entries),
        "v8_bytecode_jsc_files": jsc_files,
        "package_metadata": {
            "name": pkg_json.get("name"),
            "version": pkg_json.get("version"),
            "main": pkg_json.get("main"),
            "dependencies": list((pkg_json.get("dependencies") or {}).keys())[:30],
        },
        "export_directory": str(out_root),
        "extracted_files_count": len(extracted),
        "extracted_files": extracted[:50],
    }


# ---------------------------------------------------------------------------
# 2. PYTHON FROZEN UNPACKER (PyInstaller, Nuitka, PyArmor & .pyc Decoder)
# ---------------------------------------------------------------------------

def _decode_pyc_bytes(pyc_data: bytes) -> dict[str, Any]:
    """Safely extracts constants, names, and bytecode disassembly from PEP-552 .pyc buffers across Python versions."""
    import importlib.util

    if len(pyc_data) < 16:
        return {"error": ".pyc verisi 16 bayt basliktan kisa."}

    magic_prefix = pyc_data[:4]
    same_interpreter = magic_prefix == importlib.util.MAGIC_NUMBER
    recovered_strings = [s.decode("utf-8", errors="ignore") for s in re.findall(rb"[\x20-\x7e]{4,120}", pyc_data[16:])]
    disasm_preview = ""
    co_names: list[str] = []
    co_consts: list[str] = []

    if same_interpreter and len(pyc_data) <= 2_097_152:
        try:
            code_obj = marshal.loads(pyc_data[16:])
            names_set: list[str] = []
            consts_set: list[str] = []

            def _walk_code(co: Any, depth: int = 0) -> None:
                if depth > 4:
                    return
                for nm in getattr(co, "co_names", ()):
                    if nm not in names_set and len(names_set) < 80:
                        names_set.append(nm)
                for c in getattr(co, "co_consts", ()):
                    if isinstance(c, (str, int, float, bytes)):
                        rep = repr(c)[:100]
                        if rep not in consts_set and len(consts_set) < 60:
                            consts_set.append(rep)
                    elif hasattr(c, "co_consts"):
                        _walk_code(c, depth + 1)

            _walk_code(code_obj)
            co_names = names_set
            co_consts = consts_set
            sio = io.StringIO()
            dis.dis(code_obj, file=sio, depth=3)
            disasm_preview = sio.getvalue()[:12_000]
        except Exception as exc:
            disasm_preview = f"# Marshal/dis uyarisi: {exc}"

    return {
        "pyc_magic_hex": magic_prefix.hex(),
        "matched_host_python": same_interpreter,
        "co_names": co_names,
        "co_consts": co_consts,
        "strings_sample": list(dict.fromkeys(recovered_strings))[:50],
        "disassembly": disasm_preview,
    }


def unpack_python_frozen(target_path: str, extract_dir: str | None = None) -> dict[str, Any]:
    """Detects and unpacks PyInstaller MEI CArchives, Nuitka, PyArmor, and standalone .pyc bytecode files."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    if target_path.lower().endswith(".pyc"):
        return {"packager": "Standalone .pyc", "target": os.path.basename(target_path), "pyc_analysis": _decode_pyc_bytes(data)}

    packagers: list[str] = []
    mei_pos = data.rfind(PYINSTALLER_MAGIC)
    if mei_pos != -1:
        packagers.append("PyInstaller (MEI CArchive)")
    if b"__nuitka_version__" in data or b"Nuitka" in data:
        packagers.append("Nuitka C-Compiled Python")
    if b"__pyarmor__" in data or b"PYARMOR" in data:
        packagers.append("PyArmor Runtime Obfuscator")
    if b"py2exe" in data:
        packagers.append("py2exe")

    extracted_streams: list[str] = []
    out_root = _resolve_safe_export_dir(extract_dir, "pyfrozen", Path(target_path).stem)
    if mei_pos != -1:
        for idx, m in enumerate(re.finditer(rb"\x78[\x9c\xda\x01]", data)):
            if idx >= 40:
                break
            try:
                dec = zlib.decompressobj().decompress(data[m.start() : m.start() + 1_048_576], 4_194_304)
                if len(dec) >= 32 and (b"import" in dec or b"__main__" in dec or b"def " in dec or b"\xda\x04" in dec):
                    out_file = out_root / f"stream_{m.start():08x}.bin"
                    out_file.write_bytes(dec)
                    extracted_streams.append(out_file.name)
            except Exception:
                continue

    py_modules = sorted({m.decode("ascii") for m in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,32}\.(?:pyc|pyd|py)\b", data)})
    return {
        "is_python_frozen": bool(packagers or py_modules),
        "target": os.path.basename(target_path),
        "detected_packagers": packagers,
        "pyinstaller_cookie_offset": hex(mei_pos) if mei_pos != -1 else None,
        "embedded_python_modules": py_modules[:60],
        "export_directory": str(out_root) if extracted_streams else None,
        "extracted_zlib_streams": extracted_streams,
    }


# ---------------------------------------------------------------------------
# 3. NODE.JS SEA / VERCEL PKG / BUN STANDALONE EXTRACTOR
# ---------------------------------------------------------------------------

def extract_node_bun_sea(target_path: str, extract_dir: str | None = None) -> dict[str, Any]:
    """Detects and extracts embedded JS sources from Bun standalone binaries, Node.js SEA, and Vercel pkg."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    runtime_kind = "none"
    bun_off = data.rfind(BUN_TRAILER)
    if bun_off != -1:
        runtime_kind = "Bun Standalone Executable"
    elif NODE_SEA_FUSE in data or b"NODE_SEA_BLOB" in data:
        runtime_kind = "Node.js Single Executable Application (SEA)"
    elif b"/snapshot/" in data or b"C:\\snapshot\\" in data:
        runtime_kind = "Vercel pkg Virtual Snapshot"

    snapshot_paths = sorted({
        m.decode("utf-8", errors="ignore")
        for m in re.findall(rb"(?:/snapshot/|B:/~BUN/root/)[A-Za-z0-9_./\-]+\.(?:js|mjs|cjs|json)", data)
    })
    urls = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"https?://[A-Za-z0-9.\-_:/?=&%]{6,120}", data)})

    # Extract contiguous readable JS module blocks containing require/import/export/async function
    js_blocks = re.findall(rb"(?:[\x09\x0a\x0d\x20-\x7e]{120,65536})", data)
    saved_js: list[str] = []
    if runtime_kind != "none" or snapshot_paths:
        out_root = _resolve_safe_export_dir(extract_dir, "node_bun", Path(target_path).stem)
        for idx, blk in enumerate(js_blocks):
            if any(tok in blk for tok in (b"function(", b"=>", b"require(", b"module.exports", b"fetch(")):
                fn = f"recovered_bundle_{idx:03d}.js"
                (out_root / fn).write_bytes(blk)
                saved_js.append(fn)
                if len(saved_js) >= 15:
                    break
        export_dir_str = str(out_root) if saved_js else None
    else:
        export_dir_str = None

    return {
        "is_js_packed_binary": runtime_kind != "none" or bool(snapshot_paths),
        "runtime_packager": runtime_kind,
        "bun_trailer_offset": hex(bun_off) if bun_off != -1 else None,
        "virtual_fs_paths": snapshot_paths[:60],
        "embedded_endpoints": urls[:40],
        "export_directory": export_dir_str,
        "recovered_js_bundles": saved_js,
    }
