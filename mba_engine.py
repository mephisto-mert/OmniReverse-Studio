# -*- coding: utf-8 -*-
"""OmniReverse MBA & Cryptographic Math Deobfuscator (mba_engine.py)
Simplifies Mixed Boolean-Arithmetic (MBA) expressions, computes 64-bit modular
inverses (Hensel's Lemma), and mathematically verifies ANY bitwise/arithmetic
expression via safe AST -> Z3 64-bit BitVec compilation (zero eval/exec).
"""

from __future__ import annotations

import ast
import re
from typing import Any

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


MBA_RULES = [
    (r"\(\s*(\w+)\s*\^\s*(\w+)\s*\)\s*\+\s*2\s*\*\s*\(\s*\1\s*&\s*\2\s*\)", r"(\1 + \2)"),
    (r"2\s*\*\s*\(\s*(\w+)\s*&\s*(\w+)\s*\)\s*\+\s*\(\s*\1\s*\^\s*(\w+)\s*\)", r"(\1 + \2)"),
    (r"\(\s*(\w+)\s*\|\s*(\w+)\s*\)\s*\+\s*\(\s*\1\s*&\s*\2\s*\)", r"(\1 + \2)"),
    (r"\(\s*(\w+)\s*\+\s*(\w+)\s*\)\s*-\s*(\w+)\s*(?=)", None),  # handled dynamically if \1 == \3 or \2 == \3
    (r"\(\s*(\w+)\s*\^\s*(\w+)\s*\)\s*\+\s*2\s*\*\s*\(\s*~\s*\1\s*&\s*\2\s*\)", r"(2 * \2 - \1)"),
    (r"\(\s*(\w+)\s*\|\s*(\w+)\s*\)\s*-\s*\(\s*\1\s*&\s*\2\s*\)", r"(\1 ^ \2)"),
    (r"\(\s*(\w+)\s*\^\s*~\s*(\w+)\s*\)\s*&\s*\1", r"(\1 & \2)"),
    (r"~\s*\(\s*~\s*(\w+)\s*\)", r"\1"),
    (r"-\s*~\s*(\w+)", r"(\1 + 1)"),
    (r"~\s*-\s*(\w+)", r"(\1 - 1)"),
]


def _ast_to_z3_bitvec(expr_str: str, env: dict[str, Any]) -> Any:
    """Safely compiles a Python bitwise/arithmetic AST into a 64-bit Z3 BitVec."""
    tree = ast.parse(expr_str, mode="eval")

    def _visit(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return _visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return z3.BitVecVal(node.value & 0xFFFFFFFFFFFFFFFF, 64)
        if isinstance(node, ast.Name):
            if node.id not in env:
                env[node.id] = z3.BitVec(node.id, 64)
            return env[node.id]
        if isinstance(node, ast.UnaryOp):
            operand = _visit(node.operand)
            if isinstance(node.op, ast.Invert):
                return ~operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return operand
            raise ValueError(f"Unsupported unary op: {type(node.op).__name__}")
        if isinstance(node, ast.BinOp):
            left = _visit(node.left)
            right = _visit(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.RShift):
                return z3.LShR(left, right)
            raise ValueError(f"Unsupported binary op: {type(node.op).__name__}")
        raise ValueError(f"Disallowed AST node: {type(node).__name__}")

    return _visit(tree)


def verify_mba_equivalence_z3(expr_a: str, expr_b: str) -> bool | None:
    """Proves 64-bit equivalence of two bitwise/arithmetic expressions using Z3 SMT."""
    if not HAS_Z3:
        return None
    try:
        env: dict[str, Any] = {}
        bv_a = _ast_to_z3_bitvec(expr_a, env)
        bv_b = _ast_to_z3_bitvec(expr_b, env)
        solver = z3.Solver()
        solver.set("timeout", 3000)
        solver.add(bv_a != bv_b)
        res = solver.check()
        if res == z3.unsat:
            return True
        if res == z3.sat:
            return False
        return None
    except Exception:
        return None


def simplify_mba_expression(expr_str: str) -> dict[str, Any]:
    """Simplifies obfuscated Mixed Boolean-Arithmetic expressions and proves equivalence via Z3."""
    if not isinstance(expr_str, str) or not expr_str.strip():
        return {"error": "Bos MBA ifadesi."}
    if len(expr_str) > 2048:
        return {"error": "MBA ifadesi cok uzun (>2048 karakter)."}

    cleaned = expr_str.strip()
    steps = []

    for _ in range(6):
        prev = cleaned
        # Identity: ((A ^ B) + 2*(A & B)) - A -> B
        cleaned = re.sub(
            r"\(\s*\(\s*(\w+)\s*\^\s*(\w+)\s*\)\s*\+\s*2\s*\*\s*\(\s*\1\s*&\s*\2\s*\)\s*\)\s*-\s*\1\b",
            r"\2",
            cleaned,
        )
        for pat, repl in MBA_RULES:
            if repl is None:
                continue
            new_s = re.sub(pat, repl, cleaned)
            if new_s != cleaned:
                steps.append(f"{cleaned}  ==>  {new_s}")
                cleaned = new_s
        # Cancel (X + Y) - X -> Y or (Y + X) - X -> Y
        new_cancel = re.sub(r"\(\s*(\w+)\s*\+\s*(\w+)\s*\)\s*-\s*\1\b", r"\2", cleaned)
        new_cancel = re.sub(r"\(\s*(\w+)\s*\+\s*(\w+)\s*\)\s*-\s*\2\b", r"\1", new_cancel)
        if new_cancel != cleaned:
            steps.append(f"{cleaned}  ==>  {new_cancel}")
            cleaned = new_cancel
        if cleaned == prev:
            break

    verified = verify_mba_equivalence_z3(expr_str, cleaned)

    return {
        "original": expr_str,
        "simplified": cleaned,
        "rewrite_steps": steps,
        "smt_verified": verified,
    }


def modular_inverse_64(odd_constant: int, bits: int = 64) -> dict[str, Any]:
    """Computes multiplicative inverse modulo 2^bits using Hensel's Lemma (Newton-Raphson)."""
    if bits not in (8, 16, 32, 64, 128):
        return {"error": f"Desteklenmeyen bit genisligi: {bits}"}
    if odd_constant % 2 == 0:
        return {"error": f"Mod 2^{bits} altinda cift sayilarin ({odd_constant}) carpimsal tersi yoktur."}

    mod = 1 << bits
    mask = mod - 1
    c = odd_constant & mask

    inv = 1
    for _ in range(7):  # 2^(2^7) = 2^128 precision
        inv = (inv * (2 - c * inv)) & mask

    check = (c * inv) & mask
    return {
        "constant_hex": hex(c),
        "bits": bits,
        "inverse_hex": hex(inv),
        "inverse_dec": inv,
        "verified": check == 1,
        "formula": f"(x * {hex(c)}) mod 2^{bits} == y  ==>  x == (y * {hex(inv)}) mod 2^{bits}",
    }


def hensel_lift_polynomial_inverse(odd_constant: int, bits: int = 64) -> int:
    """Computes the exact 2^bits Hensel-lifted multiplicative root x such that (odd_constant * x) == 1 (mod 2^bits)."""
    if bits not in (8, 16, 32, 64, 128):
        raise ValueError(f"Desteklenmeyen bit genisligi: {bits}")
    if odd_constant % 2 == 0:
        raise ValueError(f"Mod 2^{bits} altinda cift sayilarin ({odd_constant}) tersi yoktur.")
    mask = (1 << bits) - 1
    c = odd_constant & mask
    x = 1
    for _ in range(7):
        x = (x * (2 - c * x)) & mask
    return x
