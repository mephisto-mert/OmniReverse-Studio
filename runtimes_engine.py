"""OmniReverse Runtimes Engine (runtimes_engine.py)
Recovers symbols and metadata from specialized runtimes:
- Go (pclntab symbol recovery, buildinfo, dependencies)
- Rust (cargo-auditable .dep-v0 decompression, rustc symbol demangling)
- Flutter / Dart (engine identification, snapshot parsing, asset manifests)
"""

from __future__ import annotations

import json
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any

from omni_config import MAX_ZLIB_DECOMPRESS_BYTES, safe_read_binary, safe_zip_read

# Binary helpers
try:
    import pefile
except ImportError:
    pefile = None


# ==========================================
# 1. GO BINARY RECOVERY (pclntab & buildinfo)
# ==========================================

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
GO_MODULE_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
GO_MODULE_END = bytes.fromhex("f932433186182072008242104116d8f2")


def inspect_go_binary(target_path: str, raw_data: bytes | None = None) -> dict[str, Any]:
    """Inspects a Go binary (PE, ELF, Mach-O) and extracts buildinfo, Go version, and symbols."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    try:
        data = raw_data if raw_data is not None else safe_read_binary(target_path)

        report: dict[str, Any] = {
            "runtime": "Go",
            "is_go": False,
            "go_version": None,
            "path": None,
            "main_pkg": None,
            "modules": [],
            "symbols_recovered": [],
            "pclntab_found": False
        }

        # 1. Search buildinfo magic
        magic_idx = data.find(GO_BUILDINFO_MAGIC)
        if magic_idx != -1:
            report["is_go"] = True
            hdr_bytes = data[magic_idx : magic_idx + 32]
            if len(hdr_bytes) >= 16:
                ptr_size = hdr_bytes[14]
                endianness = "<" if hdr_bytes[15] == 0 else ">"

                # Parse Go version string near magic
                ver_match = re.search(rb"go1\.[0-9]+(\.[0-9]+)?", data[magic_idx:magic_idx + 256])
                if ver_match:
                    report["go_version"] = ver_match.group(0).decode("latin1", errors="ignore")

        # 2. Extract embedded module dependencies
        mod_start = data.find(GO_MODULE_START)
        if mod_start != -1:
            report["is_go"] = True
            mod_end = data.find(GO_MODULE_END, mod_start + 16)
            if mod_end != -1:
                raw_mod = data[mod_start + 16 : mod_end].decode("utf-8", errors="ignore")
                lines = [line.strip() for line in raw_mod.splitlines() if line.strip()]
                for line in lines:
                    if line.startswith("path "):
                        report["path"] = line.split(" ", 1)[1]
                    elif line.startswith("mod "):
                        report["main_pkg"] = line.split(" ", 1)[1]
                    elif line.startswith("dep ") or line.startswith("\t"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            report["modules"].append({"name": parts[0], "version": parts[1]})

        # 3. Search pclntab magic headers (Go 1.2, 1.16, 1.18, 1.20)
        # Header format: [4 bytes magic] [0x00 0x00] [quantum: 1 or 4] [ptrSize: 4 or 8]
        pclntab_magics = [
            b"\xfb\xff\xff\xff\x00\x00\x01\x08", b"\xfb\xff\xff\xff\x00\x00\x01\x04",
            b"\xfa\xff\xff\xff\x00\x00\x01\x08", b"\xfa\xff\xff\xff\x00\x00\x01\x04",
            b"\xf0\xff\xff\xff\x00\x00\x01\x08", b"\xf0\xff\xff\xff\x00\x00\x01\x04",
            b"\xe0\xff\xff\xff\x00\x00\x01\x08", b"\xe0\xff\xff\xff\x00\x00\x01\x04"
        ]
        for p_magic in pclntab_magics:
            idx = data.find(p_magic)
            if idx != -1:
                # Require runtime string evidence to avoid false positives in non-Go binaries
                if b"runtime." in data or b"main." in data:
                    report["pclntab_found"] = True
                    report["is_go"] = True
                    break

        # Fast string-based symbol heuristic for stripped Go functions
        if report["is_go"]:
            go_func_matches = re.findall(rb"(?:main|runtime|net/http|github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)\.[a-zA-Z0-9_.]+", data)
            seen = set()
            for gf in go_func_matches[:100]:
                dec = gf.decode("latin1", errors="ignore")
                if dec not in seen:
                    seen.add(dec)
                    report["symbols_recovered"].append(dec)

        if not report["is_go"] and not report["symbols_recovered"]:
            return {"runtime": "Go", "is_go": False, "message": "Go calisma zamani veya buildinfo tespit edilmedi."}

        return report

    except Exception as e:
        return {"error": f"Go analizi hatasi: {str(e)}"}


# ==========================================
# 2. RUST BINARY RECOVERY (cargo-auditable & symbols)
# ==========================================

RUST_AUDITABLE_SECTION = b".dep-v0"


def inspect_rust_binary(target_path: str, raw_data: bytes | None = None) -> dict[str, Any]:
    """Inspects a Rust binary, decompresses cargo-auditable dependency records safely, and demangles Rust symbols."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    try:
        data = raw_data if raw_data is not None else safe_read_binary(target_path)

        report: dict[str, Any] = {
            "runtime": "Rust",
            "is_rust": False,
            "cargo_auditable_found": False,
            "rustc_version": None,
            "packages": [],
            "demangled_symbols": []
        }

        # 1. Search for .dep-v0 section or zlib auditable stream (bounded decompression)
        sec_idx = data.find(RUST_AUDITABLE_SECTION)
        if sec_idx != -1:
            report["is_rust"] = True
            report["cargo_auditable_found"] = True
            for offset in range(sec_idx, min(sec_idx + 128, len(data) - 2)):
                if data[offset:offset+2] in [b"\x78\x9c", b"\x78\x01", b"\x78\xda"]:
                    try:
                        dobj = zlib.decompressobj()
                        decompressed = dobj.decompress(data[offset : offset + 1024 * 1024], MAX_ZLIB_DECOMPRESS_BYTES)
                        if dobj.unconsumed_tail:
                            continue
                        parsed_json = json.loads(decompressed.decode("utf-8", errors="ignore"))
                        if "packages" in parsed_json:
                            report["packages"] = parsed_json["packages"][:50]
                            break
                    except Exception:
                        pass

        # 2. Search for rustc version string
        rustc_match = re.search(rb"rustc\s+1\.[0-9]+(\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?", data)
        if rustc_match:
            report["is_rust"] = True
            report["rustc_version"] = rustc_match.group(0).decode("latin1", errors="ignore")

        # 3. Demangle Rust v0 symbols (`_R...`)
        rust_symbols = re.findall(rb"_R[a-zA-Z0-9_]{10,}", data)
        seen = set()
        for sym in rust_symbols[:50]:
            raw_sym = sym.decode("latin1", errors="ignore")
            if raw_sym not in seen:
                seen.add(raw_sym)
                # Simplified demangling representation
                clean_name = re.sub(r"[0-9]+", "::", raw_sym[2:])
                clean_name = clean_name.strip(":")
                report["demangled_symbols"].append({"raw": raw_sym, "demangled": clean_name})

        return report

    except Exception as e:
        return {"error": f"Rust analizi hatasi: {str(e)}"}


# ==========================================
# 3. FLUTTER & DART APPLICATION RECOVERY
# ==========================================

def inspect_flutter_dart(apk_or_binary_path: str) -> dict[str, Any]:
    """Inspects Flutter APK or native binary for Flutter engine, Dart snapshot, and assets."""
    if not os.path.isfile(apk_or_binary_path):
        return {"error": f"Dosya bulunamadi: {apk_or_binary_path}"}

    import zipfile

    report: dict[str, Any] = {
        "framework": "Flutter/Dart",
        "is_flutter": False,
        "engine_version": None,
        "dart_snapshot_type": None,
        "assets": []
    }

    try:
        if zipfile.is_zipfile(apk_or_binary_path):
            with zipfile.ZipFile(apk_or_binary_path, "r") as z:
                names = z.namelist()
                has_flutter_lib = any("libflutter.so" in n for n in names)
                has_flutter_assets = any("assets/flutter_assets" in n for n in names)

                if has_flutter_lib or has_flutter_assets:
                    report["is_flutter"] = True

                # Extract assets manifest
                manifest_files = [n for n in names if n.endswith("AssetManifest.json") or n.endswith("AssetManifest.bin")]
                if manifest_files:
                    try:
                        content = safe_zip_read(z, manifest_files[0], max_bytes=16 * 1024 * 1024).decode("utf-8", errors="ignore")
                        report["assets"] = list(json.loads(content).keys())[:60]
                    except Exception:
                        pass

                # Inspect libflutter.so for engine hash
                flutter_libs = [n for n in names if "libflutter.so" in n]
                if flutter_libs:
                    lib_data = safe_zip_read(z, flutter_libs[0])
                    # Engine commit hash is usually a 40-char hex string
                    hash_match = re.search(rb"[0-9a-f]{40}", lib_data[:500000])
                    if hash_match:
                        report["engine_version"] = hash_match.group(0).decode("latin1")
                    report["dart_snapshot_type"] = "AOT Compiled (libapp.so)" if any("libapp.so" in n for n in names) else "JIT Snapshot"
        else:
            # Standalone binary
            with open(apk_or_binary_path, "rb") as f:
                data = f.read(2 * 1024 * 1024)
            if b"Flutter" in data or b"dart" in data.lower():
                report["is_flutter"] = True

        return report
    except Exception as e:
        return {"error": f"Flutter/Dart analizi hatasi: {str(e)}"}
