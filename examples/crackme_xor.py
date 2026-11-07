# -*- coding: utf-8 -*-
"""
OmniReverse Crackme Challenge #1 — XOR & Rolling Key Validator
Target: Reverse the algorithm to find the 15-character access key.
"""
import sys

# Target ciphertext computed from "OMNI-REVERSE-32"
# cipher[i] = ((ord(ch) ^ i) + 0x20) & 0xFF
TARGET_CIPHER = [
    0x6F, 0x6C, 0x6C, 0x6A, 0x49, 0x77, 0x63, 0x71,
    0x6D, 0x7B, 0x79, 0x6E, 0x41, 0x5E, 0x5C
]

def check_key(user_input: str) -> bool:
    if len(user_input) != len(TARGET_CIPHER):
        return False
    for idx, ch in enumerate(user_input):
        transformed = ((ord(ch) ^ idx) + 0x20) & 0xFF
        if transformed != TARGET_CIPHER[idx]:
            return False
    return True

def solve() -> str:
    chars = []
    for idx, c in enumerate(TARGET_CIPHER):
        orig_ord = ((c - 0x20) & 0xFF) ^ idx
        chars.append(chr(orig_ord))
    return "".join(chars)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("OmniReverse Crackme #1")
        print("Usage: python crackme_xor.py <candidate_key>")
        print(f"Keygen Solution: {solve()}")
        sys.exit(1)
        
    candidate = sys.argv[1].strip()
    if check_key(candidate):
        print(f"[+] ACCESS GRANTED: Key '{candidate}' is valid!")
        sys.exit(0)
    else:
        print(f"[-] ACCESS DENIED: '{candidate}' is invalid.")
        sys.exit(1)
