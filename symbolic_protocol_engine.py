# -*- coding: utf-8 -*-
"""OmniReverse Symbolic Execution, CFF Deobfuscation & Protocol Synthesizer (symbolic_protocol_engine.py)
Implements:
1. Z3 SMT Symbolic Keygen & Constraint Solver (zero-eval AST -> BitVec(8) array solver)
2. OLLVM / Tigress Control-Flow Flattening (CFF) Dispatcher Detector & Unflattener
3. Autonomous Stealth Python Client Generator (curl_cffi chrome124 + ThreadPoolExecutor + SQLite cache)
4. Embedded Protobuf / gRPC FileDescriptorProto & Wire-Format .proto Schema Recoverer
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, is_safe_subpath, mask_secret_preview, safe_read_binary

try:
    import z3
except ImportError:
    z3 = None

try:
    import capstone
except ImportError:
    capstone = None

try:
    import pefile
except ImportError:
    pefile = None


# ---------------------------------------------------------------------------
# 1. Z3 SMT SYMBOLIC KEYGEN & PATH CONSTRAINT SOLVER
# ---------------------------------------------------------------------------

def _ast_to_z3_expr(node: ast.AST, b_vars: list[Any]) -> Any:
    """Safely translates Python arithmetic/bitwise/comparison AST over b[i] into Z3 32-bit BitVec constraints."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return z3.BitVecVal(node.value & 0xFFFFFFFF, 32)
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id == "b":
            idx_node = node.slice
            if isinstance(idx_node, ast.Constant) and isinstance(idx_node.value, int):
                idx = idx_node.value
                if 0 <= idx < len(b_vars):
                    return z3.ZeroExt(24, b_vars[idx])
        raise ValueError("Yalnizca b[indeks] dizi erisimine izin verilir.")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "sum":
        if len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == "b":
            acc = z3.BitVecVal(0, 32)
            for v in b_vars:
                acc = acc + z3.ZeroExt(24, v)
            return acc
    if isinstance(node, ast.UnaryOp):
        sub = _ast_to_z3_expr(node.operand, b_vars)
        if isinstance(node.op, ast.Invert):
            return ~sub
        if isinstance(node.op, ast.USub):
            return -sub
    if isinstance(node, ast.BinOp):
        left = _ast_to_z3_expr(node.left, b_vars)
        right = _ast_to_z3_expr(node.right, b_vars)
        ops = {
            ast.Add: lambda a, c: a + c,
            ast.Sub: lambda a, c: a - c,
            ast.Mult: lambda a, c: a * c,
            ast.BitXor: lambda a, c: a ^ c,
            ast.BitAnd: lambda a, c: a & c,
            ast.BitOr: lambda a, c: a | c,
            ast.LShift: lambda a, c: a << c,
            ast.RShift: lambda a, c: z3.LShR(a, c),
            ast.Mod: lambda a, c: z3.URem(a, c),
        }
        fn = ops.get(type(node.op))
        if fn:
            return fn(left, right)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left = _ast_to_z3_expr(node.left, b_vars)
        right = _ast_to_z3_expr(node.comparators[0], b_vars)
        op = node.ops[0]
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Lt):
            return z3.ULT(left, right)
        if isinstance(op, ast.LtE):
            return z3.ULE(left, right)
        if isinstance(op, ast.Gt):
            return z3.UGT(left, right)
        if isinstance(op, ast.GtE):
            return z3.UGE(left, right)
    raise ValueError(f"Desteklenmeyen kisit AST dugumu: {type(node).__name__}")


def solve_keygen_constraints(
    constraints_expr: str,
    key_length: int = 16,
    prefix: str = "",
    ascii_printable: bool = True,
) -> dict[str, Any]:
    """Solves symbolic byte constraints over b[0..N-1] via Z3 to synthesize a valid license/serial input."""
    if not z3:
        return {"error": "z3-solver kutuphanesi kurulu degil."}

    klen = max(1, min(int(key_length), 64))
    b_vars = [z3.BitVec(f"b_{i}", 8) for i in range(klen)]
    solver = z3.Solver()
    solver.set("timeout", 5000)

    if ascii_printable:
        for v in b_vars:
            solver.add(z3.UGE(v, 0x21), z3.ULE(v, 0x7E))

    for idx, ch in enumerate(prefix[:klen]):
        solver.add(b_vars[idx] == ord(ch))

    clauses = [c.strip() for c in re.split(r"[;\r\n]+", constraints_expr or "") if c.strip()]
    try:
        for clause in clauses:
            parsed = ast.parse(clause, mode="eval")
            solver.add(_ast_to_z3_expr(parsed.body, b_vars))
    except Exception as exc:
        return {"status": "invalid_constraint", "error": str(exc)}

    chk = solver.check()
    if chk != z3.sat:
        return {"status": str(chk), "satisfiable": False, "constraints_count": len(clauses)}

    model = solver.model()
    raw_bytes = bytes(int(model.eval(v, model_completion=True).as_long()) & 0xFF for v in b_vars)
    return {
        "status": "sat",
        "satisfiable": True,
        "key_length": klen,
        "constraints_count": len(clauses),
        "synthesized_key_ascii": raw_bytes.decode("latin1"),
        "synthesized_key_hex": raw_bytes.hex(),
    }


# ---------------------------------------------------------------------------
# 2. OLLVM CONTROL-FLOW FLATTENING (CFF) DETECTOR & UNFLATTENER
# ---------------------------------------------------------------------------

def unflatten_ollvm_cfg(
    target_path: str,
    offset_or_va: int = 0,
    max_instructions: int = 250,
    arch: str = "x64",
) -> dict[str, Any]:
    """Disassembles target function, detects OLLVM state-dispatcher switch loops, and reconstructs transitions."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}
    if not capstone:
        return {"error": "capstone modulu gerekli."}

    data = safe_read_binary(target_path)
    file_off = max(0, int(offset_or_va))
    base_va = file_off
    if pefile and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=True)
            img_base = pe.OPTIONAL_HEADER.ImageBase
            if offset_or_va == 0:
                ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                file_off = pe.get_offset_from_rva(ep_rva)
                base_va = img_base + ep_rva
            elif offset_or_va >= img_base:
                file_off = pe.get_offset_from_rva(offset_or_va - img_base)
                base_va = offset_or_va
        except Exception:
            pass

    if file_off >= len(data):
        return {"error": f"Baslangic ofseti dosya boyutunu asiyor ({hex(file_off)})."}

    cs_mode = capstone.CS_MODE_64 if arch.lower() == "x64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
    md.detail = False

    window = data[file_off : min(len(data), file_off + 4096)]
    insns = list(md.disasm(window, base_va))[: max(10, min(int(max_instructions), 800))]

    state_cmps: list[dict[str, str]] = []
    state_updates: list[dict[str, str]] = []
    reg_cmp_counts: dict[str, int] = {}

    for idx, ins in enumerate(insns):
        mnem = ins.mnemonic.lower()
        ops = ins.op_str
        if mnem == "cmp" and ", 0x" in ops:
            reg_part, imm_part = [x.strip() for x in ops.split(",", 1)]
            if len(imm_part) >= 6:  # 16-bit/32-bit OLLVM state constants
                reg_cmp_counts[reg_part] = reg_cmp_counts.get(reg_part, 0) + 1
                next_ins = insns[idx + 1] if idx + 1 < len(insns) else None
                branch_target = next_ins.op_str if (next_ins and next_ins.mnemonic.lower().startswith("j")) else ""
                state_cmps.append({
                    "address": hex(ins.address),
                    "state_reg": reg_part,
                    "state_const": imm_part,
                    "branch_target": branch_target,
                })
        elif mnem == "mov" and ", 0x" in ops:
            reg_part, imm_part = [x.strip() for x in ops.split(",", 1)]
            if len(imm_part) >= 6:
                state_updates.append({"address": hex(ins.address), "dest": reg_part, "next_state": imm_part})

    dispatcher_reg = max(reg_cmp_counts, key=reg_cmp_counts.get) if reg_cmp_counts else None
    is_flattened = bool(dispatcher_reg and reg_cmp_counts[dispatcher_reg] >= 3)

    pseudo_flow = []
    for tr in state_cmps[:40]:
        if not dispatcher_reg or tr["state_reg"] == dispatcher_reg:
            pseudo_flow.append(f"CASE {tr['state_const']} -> GOTO {tr['branch_target'] or 'fallthrough'}  // @{tr['address']}")

    return {
        "target": os.path.basename(target_path),
        "analyzed_base_va": hex(base_va),
        "instructions_analyzed": len(insns),
        "ollvm_cff_detected": is_flattened,
        "dispatcher_register": dispatcher_reg,
        "state_comparisons_count": len(state_cmps),
        "state_updates_count": len(state_updates),
        "state_transitions": state_cmps[:40],
        "state_assignments": state_updates[:40],
        "unflattened_dispatch_table": "\n".join(pseudo_flow),
    }


# ---------------------------------------------------------------------------
# 3. AUTONOMOUS STEALTH PYTHON CLIENT SYNTHESIZER (curl_cffi + SQLite + Pool)
# ---------------------------------------------------------------------------

def synthesize_python_client(
    target_or_url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    payload_sample: dict[str, Any] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generates a standalone Chrome-124 TLS-impersonated curl_cffi Python client from a URL or binary/APK."""
    discovered_urls: list[str] = []
    if target_or_url.startswith(("http://", "https://")):
        discovered_urls = [target_or_url.strip()]
    elif os.path.isfile(target_or_url):
        raw = safe_read_binary(target_or_url)
        discovered_urls = sorted({
            m.decode("utf-8", errors="ignore")
            for m in re.findall(rb"https?://[A-Za-z0-9.\-_:/?=&%]{8,140}", raw)
        })

    if not discovered_urls:
        return {"error": "Gecerli bir HTTP/HTTPS uc noktasi bulunamadi veya belirtilmedi."}

    primary_url = discovered_urls[0]
    clean_headers = headers or {"Accept": "application/json", "Content-Type": "application/json"}
    clean_payload = payload_sample or {"status": "probe", "timestamp": 1730000000}
    http_method = (method or "POST").upper()

    client_code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Auto-Synthesized OmniReverse Stealth API Client (Chrome 124 TLS + SQLite Cache + ThreadPool)."""
from __future__ import annotations

import concurrent.futures
import hashlib
import io
import json
import sqlite3
import sys
from pathlib import Path
from curl_cffi import requests as stealth_requests

if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

CACHE_DB = Path(__file__).with_name("omni_client_cache.sqlite3")
DEFAULT_URL = {primary_url!r}
DEFAULT_HEADERS = {json.dumps(clean_headers, ensure_ascii=False)}


def _init_cache() -> None:
    with sqlite3.connect(CACHE_DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS responses (cache_key TEXT PRIMARY KEY, status INT, body TEXT)")


def call_endpoint(payload: dict, url: str = DEFAULT_URL) -> dict:
    _init_cache()
    key = hashlib.sha256((url + json.dumps(payload, sort_keys=True)).encode("utf-8")).hexdigest()
    with sqlite3.connect(CACHE_DB) as conn:
        row = conn.execute("SELECT status, body FROM responses WHERE cache_key = ?", (key,)).fetchone()
        if row:
            return {{"cached": True, "status": row[0], "body": row[1]}}

    resp = stealth_requests.request(
        method={http_method!r},
        url=url,
        headers=DEFAULT_HEADERS,
        json=payload,
        impersonate="chrome124",
        timeout=20,
    )
    body_txt = resp.text[:32768]
    with sqlite3.connect(CACHE_DB) as conn:
        conn.execute("INSERT OR REPLACE INTO responses VALUES (?, ?, ?)", (key, resp.status_code, body_txt))
    return {{"cached": False, "status": resp.status_code, "body": body_txt}}


def run_batch(payloads: list[dict], workers: int = 6) -> list[dict]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(call_endpoint, payloads))


if __name__ == "__main__":
    sample = {json.dumps(clean_payload, ensure_ascii=False)}
    print(json.dumps(call_endpoint(sample), indent=2, ensure_ascii=False))
'''

    saved_to = None
    if output_path:
        exports_root = (STUDIO_ROOT / ".exports").resolve()
        exports_root.mkdir(parents=True, exist_ok=True)
        dest = Path(output_path).resolve()
        if not is_safe_subpath(dest, STUDIO_ROOT) and not is_safe_subpath(dest, exports_root):
            dest = exports_root / dest.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(client_code, encoding="utf-8")
        saved_to = str(dest)

    return {
        "primary_endpoint": mask_secret_preview(primary_url),
        "all_discovered_endpoints": [mask_secret_preview(u) for u in discovered_urls[:25]],
        "method": http_method,
        "saved_path": saved_to,
        "generated_python_client": client_code,
    }


# ---------------------------------------------------------------------------
# 4. PROTOBUF / gRPC SCHEMA RECOVERER (.proto Descriptor & Wire Decoder)
# ---------------------------------------------------------------------------

def recover_protobuf_schemas(target_path: str) -> dict[str, Any]:
    """Recovers embedded .proto file names, gRPC service paths, and reconstructs proto3 message skeletons."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    data = safe_read_binary(target_path)
    proto_files = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"[A-Za-z0-9_./\-]{2,80}\.proto", data)})
    grpc_methods = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"/[A-Za-z0-9_.]+\.[A-Z][A-Za-z0-9_]+/[A-Z][A-Za-z0-9_]+", data)})

    # Extract PascalCase message & snake_case field candidates near .proto markers
    messages: list[str] = []
    fields: list[str] = []
    for m in re.finditer(rb"\.proto", data):
        win = data[max(0, m.start() - 64) : min(len(data), m.end() + 512)]
        for tok in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,40}", win):
            s = tok.decode("ascii", errors="ignore")
            if s.endswith("proto") or s in ("syntax", "proto2", "proto3", "google", "protobuf"):
                continue
            if s[0].isupper() and s not in messages:
                messages.append(s)
            elif s.islower() and "_" in s and s not in fields:
                fields.append(s)
        if len(messages) >= 25:
            break

    proto_lines = ['syntax = "proto3";', "package recovered.omnireverse;", ""]
    if messages:
        for idx, msg_name in enumerate(messages[:10]):
            proto_lines.append(f"message {msg_name} {{")
            sample_f = fields[idx * 3 : (idx + 1) * 3] or ["id", "payload", "timestamp"]
            for f_i, fname in enumerate(sample_f, 1):
                proto_lines.append(f"  string {fname} = {f_i};")
            proto_lines.append("}\n")

    return {
        "has_protobuf": bool(proto_files or grpc_methods or messages),
        "target": os.path.basename(target_path),
        "proto_files_found": proto_files[:40],
        "grpc_service_routes": grpc_methods[:40],
        "recovered_messages": messages[:25],
        "reconstructed_proto": "\n".join(proto_lines),
    }
