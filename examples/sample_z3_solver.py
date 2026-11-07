# -*- coding: utf-8 -*-
"""
OmniReverse Z3 MBA Solver & Deobfuscator Example
Demonstrates unrolling Mixed Boolean-Arithmetic (MBA) obfuscation and
calculating 64-bit modular inverses to undo opaque constant multiplication.
"""
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mba_engine import simplify_mba_expression, modular_inverse_64, hensel_lift_polynomial_inverse

def main():
    print("=================================================================")
    print("  OmniReverse Studio — Z3 MBA Solver & Deobfuscation Showcase")
    print("=================================================================\n")

    # 1. Complex MBA expression (common in OLLVM and Tigress obfuscators)
    # Identity: (x ^ y) + 2 * (x & y) == x + y
    mba_expr = "(x ^ y) + 2 * (x & y)"
    print(f"[*] Analyzing MBA Obfuscated Expression: {mba_expr}")
    result = simplify_mba_expression(mba_expr)
    print(f"[+] Z3 Simplified Canonical Form: {result.get('simplified_expression', result)}\n")

    # 2. 64-bit Modular Inverses (used in reversing compiler optimizations & anti-tamper hashes)
    odd_const = 0x1337C0DEBEEF0001
    print(f"[*] Computing 64-bit Modular Inverse for Constant: {hex(odd_const)}")
    inv_info = modular_inverse_64(odd_const)
    inv_val = inv_info.get("inverse_hex", "N/A")
    print(f"[+] Computed Modular Inverse: {inv_val}")
    
    # Verification: (a * a_inv) mod 2^64 == 1
    if "inverse_dec" in inv_info:
        product = (odd_const * inv_info["inverse_dec"]) & 0xFFFFFFFFFFFFFFFF
        print(f"[+] Verification: ({hex(odd_const)} * {inv_val}) mod 2^64 = {hex(product)}")
        assert product == 1, "Modular inverse verification failed!"
        print("    [Status: VERIFIED OK]")

    # 3. Hensel Lifting Inverse
    print("\n[*] Computing Hensel Lifting Polynomial Inverse:")
    hensel_res = hex(hensel_lift_polynomial_inverse(odd_const))
    print(f"[+] Hensel Lift: {hensel_res}")
    print("\n[+] All Z3 MBA deobfuscation checks completed successfully.")

if __name__ == "__main__":
    main()
