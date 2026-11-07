# -*- coding: utf-8 -*-
"""OmniReverse MCP v3.2 Extensions Engine (mcp_extensions_engine.py)
Implements:
1. SQLite FTS5 Function Signature & Binary Fingerprint Vault (omni_bsim_vault — FLIRT / BSim style)
2. IDAPython, Ghidra, Binary Ninja & x64dbg Annotation/IAT Exporter (omni_export_annotations)
3. PE RSDS PDB Symbol Resolver, Encrypted Vault Header Inspector & HAR -> OpenAPI 3.1 Synthesizer (omni_pdb_traffic_correlate)
4. Autonomous Format-Aware Multi-Engine Orchestrator (omni_auto_orchestrate)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import struct
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, is_safe_subpath, safe_read_binary

try:
    import capstone
except ImportError:
    capstone = None

try:
    import pefile
except ImportError:
    pefile = None

BSIM_DB_PATH = (STUDIO_ROOT / ".sessions" / "omni_bsim_vault.sqlite3").resolve()


def _init_bsim_db() -> sqlite3.Connection:
    BSIM_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(BSIM_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS func_signatures (
            sig_hash TEXT PRIMARY KEY,
            binary_name TEXT,
            binary_sha256 TEXT,
            func_va TEXT,
            func_label TEXT,
            prologue_hex TEXT,
            mnemonic_pattern TEXT,
            size_hint INT
        )
        """
    )
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS func_fts USING fts5(
            sig_hash, binary_name, func_label, mnemonic_pattern
        )
        """
    )
    return conn


def _extract_prologue_signatures(data: bytes, max_funcs: int = 120) -> list[dict[str, Any]]:
    base_va = 0x140001000
    exec_blob = data[: min(len(data), 524_288)]
    if pefile and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=True)
            img_base = pe.OPTIONAL_HEADER.ImageBase
            for sec in pe.sections:
                if sec.Characteristics & 0x20000000:
                    exec_blob = sec.get_data()[:524_288]
                    base_va = img_base + sec.VirtualAddress
                    break
        except Exception:
            pass

    prologues = re.finditer(
        rb"(?:\x48\x89\x5c\x24|\x48\x83\xec|\x40\x53\x48\x83\xec|\x55\x48\x89\xe5|\x40\x55\x53|\x48\x8b\xc4)",
        exec_blob,
    )
    items: list[dict[str, Any]] = []
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64) if capstone else None

    for idx, m in enumerate(prologues):
        if idx >= max_funcs:
            break
        off = m.start()
        window = exec_blob[off : off + 32]
        if len(window) < 12:
            continue
        va = base_va + off
        if md:
            insns = list(md.disasm(window, va))[:8]
            mnem_pat = " ; ".join(i.mnemonic for i in insns)
            norm_bytes = b"".join(bytes(i.bytes[:2]) for i in insns)
        else:
            mnem_pat = "raw_x64_prologue"
            norm_bytes = window[:16]
        sig_hash = hashlib.sha256(norm_bytes + mnem_pat.encode("ascii", errors="ignore")).hexdigest()[:24]
        items.append({
            "sig_hash": sig_hash,
            "func_va": hex(va),
            "func_label": f"sub_{va:x}",
            "prologue_hex": window[:16].hex(),
            "mnemonic_pattern": mnem_pat,
            "size_hint": len(window),
        })
    return items


def bsim_vault_action(
    action: str,
    target_path: str = "",
    query_or_label_prefix: str = "",
) -> dict[str, Any]:
    """Indexes binary function signatures into local SQLite FTS5 vault or matches stripped functions."""
    act = (action or "match_functions").strip().lower()
    if act == "search_vault":
        q = (query_or_label_prefix or target_path or "push").strip()
        safe_q = re.sub(r'[^A-Za-z0-9_ ]', ' ', q).strip() or "sub"
        with _init_bsim_db() as conn:
            rows = conn.execute(
                "SELECT sig_hash, binary_name, func_label, mnemonic_pattern FROM func_fts WHERE func_fts MATCH ? LIMIT 40",
                (safe_q,),
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM func_signatures").fetchone()[0]
        return {
            "action": "search_vault",
            "query": safe_q,
            "vault_total_signatures": total,
            "matches": [
                {"sig_hash": r[0], "binary": r[1], "label": r[2], "mnemonics": r[3]}
                for r in rows
            ],
        }

    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    bin_sha = hashlib.sha256(data).hexdigest()
    bin_name = os.path.basename(target_path)
    sigs = _extract_prologue_signatures(data)

    if act == "index_binary":
        prefix = re.sub(r"[^A-Za-z0-9_]", "_", query_or_label_prefix.strip()) if query_or_label_prefix else ""
        with _init_bsim_db() as conn:
            for s in sigs:
                lbl = f"{prefix}_{s['func_label']}" if prefix else s["func_label"]
                conn.execute(
                    "INSERT OR REPLACE INTO func_signatures VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (s["sig_hash"], bin_name, bin_sha, s["func_va"], lbl, s["prologue_hex"], s["mnemonic_pattern"], s["size_hint"]),
                )
                conn.execute("DELETE FROM func_fts WHERE sig_hash = ?", (s["sig_hash"],))
                conn.execute(
                    "INSERT INTO func_fts VALUES (?, ?, ?, ?)",
                    (s["sig_hash"], bin_name, lbl, s["mnemonic_pattern"]),
                )
            total = conn.execute("SELECT COUNT(*) FROM func_signatures").fetchone()[0]
        return {
            "action": "index_binary",
            "binary": bin_name,
            "indexed_functions": len(sigs),
            "vault_total_signatures": total,
        }

    # Default: match_functions against vault
    matched: list[dict[str, str]] = []
    with _init_bsim_db() as conn:
        for s in sigs:
            row = conn.execute(
                "SELECT binary_name, func_label, mnemonic_pattern FROM func_signatures WHERE sig_hash = ?",
                (s["sig_hash"],),
            ).fetchone()
            if row:
                matched.append({
                    "target_va": s["func_va"],
                    "matched_binary": row[0],
                    "matched_label": row[1],
                    "mnemonics": row[2],
                })
    return {
        "action": "match_functions",
        "target": bin_name,
        "scanned_functions": len(sigs),
        "matched_count": len(matched),
        "matches": matched[:50],
    }


# ---------------------------------------------------------------------------
# 2. IDAPYTHON, GHIDRA, BINARY NINJA & X64DBG ANNOTATION EXPORTER
# ---------------------------------------------------------------------------

def export_annotations_script(
    session_or_target: str,
    export_format: str = "idapython",
    output_path: str | None = None,
) -> dict[str, Any]:
    """Exports session bookmarks, comments, renamed symbols & Scylla IAT slots to IDAPython, Ghidra, Binja, or x64dbg."""
    from session_engine import BinarySession

    sess_data: dict[str, Any] = {}
    target_bin = ""
    if session_or_target.startswith("sess_"):
        sess_data = BinarySession.get_session(session_or_target)
        if "error" in sess_data:
            return sess_data
        target_bin = sess_data.get("target_path", "")
    elif os.path.isfile(session_or_target):
        opened = BinarySession.open_session(session_or_target)
        sess_data = opened.get("data", {})
        target_bin = session_or_target
    else:
        return {"error": f"Gecerli bir session_id veya dosya yolu belirtin: {session_or_target}"}

    renames = dict(sess_data.get("renamed_symbols") or {})
    comments = dict(sess_data.get("comments") or {})
    bookmarks = dict(sess_data.get("bookmarks") or {})

    if target_bin and os.path.isfile(target_bin) and target_bin.lower().endswith((".exe", ".dll", ".sys")):
        try:
            from native_packer_engine import reconstruct_iat_scylla
            iat = reconstruct_iat_scylla(target_bin)
            for item in (iat.get("resolved_sample") or [])[:40]:
                va_k = item.get("slot_va", "")
                sym_v = re.sub(r"[^A-Za-z0-9_]", "_", item.get("symbol", ""))
                if va_k and sym_v and va_k not in renames:
                    renames[va_k] = f"iat_{sym_v}"
        except Exception:
            pass

    fmt = (export_format or "idapython").strip().lower()
    if fmt == "ghidra":
        lines = ["# OmniReverse Studio v3.2 - Ghidra Headless/GUI Import Script", "from ghidra.program.model.symbol import SourceType", ""]
        for addr, name in renames.items():
            lines.append(f'createLabel(toAddr({addr!r}), {name!r}, True, SourceType.USER_DEFINED)')
        for addr, txt in {**bookmarks, **comments}.items():
            lines.append(f'setEOLComment(toAddr({addr!r}), {txt!r})')
        content_out = "\n".join(lines) + "\n"
        ext = ".py"
    elif fmt == "binja":
        lines = ["# OmniReverse Studio v3.2 - Binary Ninja Import Script", "import binaryninja as bn", ""]
        for addr, name in renames.items():
            lines.append(f"bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, int({addr!r}, 16), {name!r}))")
        for addr, txt in {**bookmarks, **comments}.items():
            lines.append(f"bv.set_comment_at(int({addr!r}, 16), {txt!r})")
        content_out = "\n".join(lines) + "\n"
        ext = ".py"
    elif fmt == "x64dbg":
        db_obj = {
            "labels": [{"module": os.path.basename(target_bin or "target.exe"), "address": a, "text": n} for a, n in renames.items()],
            "comments": [{"module": os.path.basename(target_bin or "target.exe"), "address": a, "text": c} for a, c in {**bookmarks, **comments}.items()],
        }
        content_out = json.dumps(db_obj, indent=2, ensure_ascii=False)
        ext = ".dd64.json"
    else:
        fmt = "idapython"
        lines = ["# OmniReverse Studio v3.2 - IDAPython Import Script", "import idc, ida_name", ""]
        for addr, name in renames.items():
            lines.append(f"ida_name.set_name(int({addr!r}, 16), {name!r}, ida_name.SN_NOCHECK)")
        for addr, txt in {**bookmarks, **comments}.items():
            lines.append(f"idc.set_cmt(int({addr!r}, 16), {txt!r}, 0)")
        content_out = "\n".join(lines) + "\n"
        ext = ".py"

    exports_dir = (STUDIO_ROOT / ".exports").resolve()
    exports_dir.mkdir(parents=True, exist_ok=True)
    stem = sess_data.get("session_id") or Path(target_bin or "omni").stem
    dest = Path(output_path).resolve() if output_path else (exports_dir / f"{stem}_{fmt}{ext}")
    if not is_safe_subpath(dest, STUDIO_ROOT) and not is_safe_subpath(dest, exports_dir):
        dest = exports_dir / f"{stem}_{fmt}{ext}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content_out, encoding="utf-8")

    return {
        "format": fmt,
        "exported_file": str(dest),
        "renames_count": len(renames),
        "comments_count": len(comments) + len(bookmarks),
        "script_preview": content_out[:4000],
    }


# ---------------------------------------------------------------------------
# 3. PDB RSDS RESOLVER, VAULT HEADER INSPECTOR & HAR -> OPENAPI SYNTHESIZER
# ---------------------------------------------------------------------------

def pdb_and_traffic_correlate(action: str, target_path: str) -> dict[str, Any]:
    """Extracts PE RSDS PDB GUID/Symbol URLs, inspects SQLCipher/DPAPI/Keystore headers, or builds OpenAPI 3.1 from HAR."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    act = (action or "pdb_info").strip().lower()
    data = safe_read_binary(target_path)

    if act == "pdb_info":
        pos = data.find(b"RSDS")
        if pos == -1 or pos + 24 > len(data):
            return {"has_rsds_pdb": False, "target": os.path.basename(target_path)}
        d1, d2, d3 = struct.unpack_from("<IHH", data, pos + 4)
        d4 = data[pos + 12 : pos + 20]
        age = struct.unpack_from("<I", data, pos + 20)[0]
        end_str = data.find(b"\x00", pos + 24)
        pdb_path = data[pos + 24 : (end_str if end_str != -1 else pos + 260)].decode("utf-8", errors="ignore")
        pdb_name = os.path.basename(pdb_path.replace("\\", "/")) or "symbols.pdb"
        guid_sym = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}{age:X}"
        return {
            "has_rsds_pdb": True,
            "pdb_path": pdb_path,
            "pdb_filename": pdb_name,
            "rsds_guid_age": guid_sym,
            "msdl_symbol_url": f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid_sym}/{pdb_name}",
        }

    if act == "vault_headers":
        findings: list[str] = []
        if data[:16] == b"SQLite format 3\x00":
            findings.append("Plaintext SQLite 3 Database Header")
        elif len(data) >= 64 and data[:16] != b"SQLite format 3\x00" and target_path.lower().endswith((".db", ".sqlite", ".sqlite3")):
            findings.append("Encrypted SQLite / SQLCipher Candidate (High-Entropy Salt Header)")
        if b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb" in data:
            findings.append("Windows DPAPI CryptProtectData Blob (GUID d08c9ddf-0115-d111-8c7a-00c04fc297eb)")
        if data[:4] == b"\xfe\xed\xfe\xed":
            findings.append("Java KeyStore (JKS) Container")
        if b"AndroidKeyStore" in data or b"EncryptedSharedPreferences" in data:
            findings.append("Android Keystore / Jetpack EncryptedSharedPreferences Reference")
        return {"target": os.path.basename(target_path), "vault_indicators": findings}

    # har_to_openapi: convert HAR or JSON request array into OpenAPI 3.1 spec
    try:
        har_obj = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception as exc:
        return {"error": f"HAR/JSON okunamadi: {exc}"}

    entries = ((har_obj.get("log") or {}).get("entries")) if isinstance(har_obj, dict) else None
    if not isinstance(entries, list):
        entries = har_obj if isinstance(har_obj, list) else []

    paths_spec: dict[str, Any] = {}
    hosts: set[str] = set()
    for ent in entries[:300]:
        req = ent.get("request", ent) if isinstance(ent, dict) else {}
        url = str(req.get("url", ""))
        method = str(req.get("method", "GET")).lower()
        m = re.match(r"^(https?://[^/]+)(/[^?#]*)?", url)
        if not m:
            continue
        hosts.add(m.group(1))
        route = m.group(2) or "/"
        paths_spec.setdefault(route, {})[method] = {
            "summary": f"Recovered {method.upper()} {route}",
            "responses": {"200": {"description": "Captured live response"}},
        }

    openapi = {
        "openapi": "3.1.0",
        "info": {"title": f"OmniReverse Recovered API ({os.path.basename(target_path)})", "version": "1.0.0"},
        "servers": [{"url": h} for h in sorted(hosts)[:10]],
        "paths": paths_spec,
    }
    return {"endpoints_recovered": len(paths_spec), "servers": sorted(hosts), "openapi_3_1": openapi}


# ---------------------------------------------------------------------------
# 4. AUTONOMOUS MULTI-ENGINE TARGET ORCHESTRATOR (omni_auto_orchestrate)
# ---------------------------------------------------------------------------

def auto_orchestrate_target(target_path: str) -> dict[str, Any]:
    """Classifies any target file by magic bytes + extension and executes the optimal OmniReverse engine chain."""
    if not target_path or not os.path.exists(target_path):
        return {"error": f"Hedef bulunamadi: {target_path}"}
    if os.path.isdir(target_path):
        from sqli_detector import audit_target
        return {"detected_kind": "source_directory", "sast_audit": audit_target(target_path, is_snippet=False)}

    ext = Path(target_path).suffix.lower()
    with open(target_path, "rb") as fp:
        head = fp.read(64)
    summary: dict[str, Any] = {"target": os.path.basename(target_path), "extension": ext, "steps_executed": []}

    if head[:2] == b"MZ" or ext in (".exe", ".dll", ".sys"):
        from native_packer_engine import inspect_dotnet_cil, reconstruct_iat_scylla, scan_direct_syscalls, synthesize_yara_and_crypto
        from visual_patch_memory_engine import build_visual_cfg
        summary["detected_kind"] = "windows_pe"
        summary["dotnet"] = inspect_dotnet_cil(target_path)
        summary["iat_scylla"] = reconstruct_iat_scylla(target_path)
        summary["direct_syscalls"] = scan_direct_syscalls(target_path)
        summary["pdb"] = pdb_and_traffic_correlate("pdb_info", target_path)
        summary["yara_crypto"] = synthesize_yara_and_crypto(target_path)
        cfg = build_visual_cfg(target_path, max_instructions=50)
        cfg.pop("svg", None)
        summary["cfg_summary"] = cfg
        summary["steps_executed"] = ["dotnet_cil", "iat_scylla", "direct_syscalls", "pdb_info", "yara_crypto", "visual_cfg"]
    elif ext in (".apk", ".ipa", ".hbc", ".dat") or head[:4] == b"PK\x03\x04":
        from mobile_deep_engine import analyze_flutter_aot_snapshot, analyze_ios_ipa_macho, decompile_hermes_bytecode, dump_unity_il2cpp
        summary["detected_kind"] = "mobile_package_or_vm"
        summary["flutter"] = analyze_flutter_aot_snapshot(target_path)
        summary["hermes"] = decompile_hermes_bytecode(target_path)
        summary["il2cpp"] = dump_unity_il2cpp(target_path)
        if ext == ".ipa":
            summary["ios"] = analyze_ios_ipa_macho(target_path)
        summary["steps_executed"] = ["flutter_aot", "hermes_hbc", "unity_il2cpp"]
    elif ext in (".asar", ".jsc", ".pyc"):
        from modern_packers_engine import unpack_electron_asar, unpack_python_frozen
        summary["detected_kind"] = "packaged_desktop_archive"
        summary["result"] = unpack_electron_asar(target_path) if ext in (".asar", ".jsc") else unpack_python_frozen(target_path)
        summary["steps_executed"] = ["modern_unpacker"]
    else:
        from native_packer_engine import synthesize_yara_and_crypto
        from symbolic_protocol_engine import recover_protobuf_schemas
        summary["detected_kind"] = "generic_binary_or_source"
        summary["yara_crypto"] = synthesize_yara_and_crypto(target_path)
        summary["protobuf"] = recover_protobuf_schemas(target_path)
        summary["vault_headers"] = pdb_and_traffic_correlate("vault_headers", target_path)
        summary["steps_executed"] = ["yara_crypto", "protobuf_recover", "vault_headers"]
    return summary
