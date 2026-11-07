# -*- coding: utf-8 -*-
"""OmniReverse WebAssembly Engine (wasm_engine.py)
Provides cross-platform WASM header inspection and WAT disassembly via WABT
plus a pure-Python binary WASM section/import/export parser fallback.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any

from omni_config import get_wabt_tool, safe_read_binary

WASM_SECTION_NAMES = {
    0: "Custom",
    1: "Type",
    2: "Import",
    3: "Function",
    4: "Table",
    5: "Memory",
    6: "Global",
    7: "Export",
    8: "Start",
    9: "Element",
    10: "Code",
    11: "Data",
    12: "DataCount",
}


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while pos < len(data) and shift <= 35:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
    raise ValueError("Truncated or invalid LEB128 integer in WASM stream")


def _parse_wasm_binary_pure(data: bytes) -> dict[str, Any]:
    """Pure-Python WebAssembly 1.0 binary parser (zero external binary dependency)."""
    if len(data) < 8 or data[:4] != b"\x00asm":
        return {"error": "Gecerli bir WebAssembly ikili dosyasi degil (\\x00asm basligi eksik)."}

    version = int.from_bytes(data[4:8], "little")
    pos = 8
    sections = []
    exports = []
    imports = []

    while pos < len(data):
        sec_id = data[pos]
        pos += 1
        sec_len, pos = _read_uleb128(data, pos)
        sec_end = min(len(data), pos + sec_len)
        sec_name = WASM_SECTION_NAMES.get(sec_id, f"Unknown({sec_id})")
        sections.append({"id": sec_id, "name": sec_name, "offset": hex(pos), "size": sec_len})

        try:
            if sec_id == 2:  # Import section
                cnt, p = _read_uleb128(data, pos)
                for _ in range(min(cnt, 50)):
                    mlen, p = _read_uleb128(data, p)
                    mod = data[p : p + mlen].decode("utf-8", errors="replace")
                    p += mlen
                    flen, p = _read_uleb128(data, p)
                    field = data[p : p + flen].decode("utf-8", errors="replace")
                    p += flen
                    kind = data[p]
                    p += 1
                    if kind == 0:
                        _, p = _read_uleb128(data, p)
                    else:
                        imports.append(f"{mod}.{field} (kind={kind})")
                        break
                    imports.append(f"{mod}.{field}")
            elif sec_id == 7:  # Export section
                cnt, p = _read_uleb128(data, pos)
                for _ in range(min(cnt, 50)):
                    nlen, p = _read_uleb128(data, p)
                    ename = data[p : p + nlen].decode("utf-8", errors="replace")
                    p += nlen
                    ekind = data[p]
                    p += 1
                    eidx, p = _read_uleb128(data, p)
                    exports.append({"name": ename, "kind": ekind, "index": eidx})
        except Exception:
            pass

        pos = sec_end

    return {
        "wasm_version": version,
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }


def disassemble_wasm(target_path: str, max_lines: int = 150) -> dict[str, Any]:
    """Disassembles a .wasm binary module into WAT via WABT or pure-Python structuralWAT."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Hedef dosya bulunamadi: {target_path}"}

    max_lines = max(1, min(int(max_lines), 1000))
    wasm2wat = get_wabt_tool("wasm2wat")

    if wasm2wat and wasm2wat.is_file():
        proc = None
        try:
            cmd = [str(wasm2wat), os.path.abspath(target_path), "--generate-names"]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            lines = []
            assert proc.stdout is not None
            for _ in range(max_lines):
                line = proc.stdout.readline()
                if not line:
                    break
                lines.append(line.rstrip("\r\n"))
            proc.kill()
            _, stderr_out = proc.communicate(timeout=5)
            if not lines and stderr_out:
                return {"error": f"wasm2wat hatasi: {stderr_out[:1000]}"}
            return {
                "status": "success",
                "engine": "wabt",
                "target": os.path.basename(target_path),
                "format": "wat",
                "preview_lines_count": len(lines),
                "wat_preview": "\n".join(lines),
            }
        except Exception as e:
            return {"error": f"WASM disassembly hatasi: {str(e)}"}
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass

    # Pure-Python fallback when WABT CLI is not installed
    try:
        raw = safe_read_binary(target_path, max_bytes=64 * 1024 * 1024)
        parsed = _parse_wasm_binary_pure(raw)
        if "error" in parsed:
            return parsed
        wat_lines = [f"(module ;; WASM v{parsed['wasm_version']} (Pure-Python Structural Disassembly)"]
        for imp in parsed["imports"]:
            wat_lines.append(f'  (import "{imp}")')
        for exp in parsed["exports"]:
            wat_lines.append(f'  (export "{exp["name"]}" (index {exp["index"]}))')
        for sec in parsed["sections"]:
            wat_lines.append(f"  ;; section {sec['name']} @ {sec['offset']} ({sec['size']} bytes)")
        wat_lines.append(")")
        return {
            "status": "success",
            "engine": "pure_python_fallback",
            "target": os.path.basename(target_path),
            "format": "wat",
            "preview_lines_count": len(wat_lines[:max_lines]),
            "wat_preview": "\n".join(wat_lines[:max_lines]),
        }
    except Exception as e:
        return {"error": f"WASM okuma hatasi: {str(e)}"}


def inspect_wasm_headers(target_path: str) -> dict[str, Any]:
    """Inspects WASM imports, exports, and sections via wasm-objdump or pure-Python fallback."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Hedef dosya bulunamadi: {target_path}"}

    objdump = get_wabt_tool("wasm-objdump")
    if objdump and objdump.is_file():
        try:
            cmd = [str(objdump), "-h", "-x", os.path.abspath(target_path)]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if res.returncode != 0:
                return {"error": f"wasm-objdump hatasi: {res.stderr[:1000]}"}
            return {
                "status": "success",
                "engine": "wabt",
                "target": os.path.basename(target_path),
                "objdump_summary": res.stdout[:5000],
            }
        except Exception as e:
            return {"error": f"WASM header ayristirma hatasi: {str(e)}"}

    try:
        raw = safe_read_binary(target_path, max_bytes=64 * 1024 * 1024)
        parsed = _parse_wasm_binary_pure(raw)
        if "error" in parsed:
            return parsed
        return {
            "status": "success",
            "engine": "pure_python_fallback",
            "target": os.path.basename(target_path),
            "parsed_headers": parsed,
        }
    except Exception as e:
        return {"error": f"WASM baslik okuma hatasi: {str(e)}"}
