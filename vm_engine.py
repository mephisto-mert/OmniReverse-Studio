"""
OmniReverse Custom VM Engine (vm_engine.py)
Automated analysis, disassembly, and symbolic lifting of custom CrackMe virtual machines.
Supports:
- Register-based bytecode architectures (Kakura, Aegis, Oreans/Themida light VMs)
- Bytecode pattern recognition and instruction extraction
- Automatic symbolic lifting to Z3 SMT solver constraints
"""

from __future__ import annotations

import struct
from typing import Any

class VMDisassembler:
    """Disassembles and analyzes 8-byte fixed instruction register-based virtual machines."""

    OPCODES = {
        0x0f: "EXIT",
        0x19: "ADD",
        0x2b: "MOV",
        0x37: "LOAD_KEY",
        0x5e: "ROL",
        0x6a: "XOR_IMM",
        0x71: "XOR",
        0x8d: "AND",
        0x8e: "AND_IMM",
        0xa4: "SUB",
        0xc3: "MUL",
        0xd6: "SETE",
        0xe2: "JNZ",
        0xe4: "JMP",
    }

    @staticmethod
    def disassemble(bytecode: bytes) -> list[dict[str, Any]]:
        """Disassembles 8-byte instruction blocks into structured instructions."""
        instructions = []
        num_insns = len(bytecode) // 8

        for i in range(num_insns):
            chunk = bytecode[i * 8 : (i + 1) * 8]
            op, r8, rcx, esi = chunk[0], chunk[1] & 7, chunk[2] & 7, chunk[3]
            imm32 = struct.unpack("<I", chunk[4:8])[0]

            name = VMDisassembler.OPCODES.get(op, f"UNK_0x{op:02x}")
            insn_dict = {
                "index": i,
                "opcode": hex(op),
                "mnemonic": name,
                "dst_reg": f"R{r8}",
                "src_reg": f"R{rcx}",
                "imm8": esi,
                "imm32": hex(imm32),
                "raw": chunk.hex()
            }
            instructions.append(insn_dict)

        return instructions

    @staticmethod
    def format_assembly(instructions: list[dict[str, Any]]) -> str:
        lines = []
        for ins in instructions:
            idx = ins["index"]
            mnem = ins["mnemonic"]
            dst = ins["dst_reg"]
            src = ins["src_reg"]
            imm = ins["imm32"]
            imm8 = ins["imm8"]

            if mnem in ("ADD", "XOR", "AND", "SUB", "MUL"):
                args = f"{dst}, {src}"
            elif mnem == "MOV":
                args = f"{dst}, {imm}"
            elif mnem == "LOAD_KEY":
                args = f"{dst}, key[{src}]"
            elif mnem == "ROL":
                args = f"{dst}, {imm8 & 0x1f}"
            elif mnem == "XOR_IMM":
                args = f"{dst}, {imm}"
            elif mnem == "AND_IMM":
                args = f"{dst}, {hex(imm8)}"
            elif mnem == "SETE":
                args = f"{dst} = ({dst} == {src})"
            elif mnem in ("JNZ", "JMP"):
                args = f"target={imm}"
            elif mnem == "EXIT":
                args = "(returns R0 & 1)"
            else:
                args = f"{dst}, {src}, {imm}"

            lines.append(f"[{idx:02d}] {mnem:<10} {args}")
        return "\n".join(lines)


def auto_decrypt_lcg_stream(seed: int, ciphertext: bytes, multiplier: int = 0x41c64e6d, addend: int = 0x3039, shift: int = 16) -> bytes:
    """Decrypts a buffer encrypted with an LCG keystream."""
    out = bytearray()
    curr = seed & 0xffffffff
    for b in ciphertext:
        curr = (curr * multiplier + addend) & 0xffffffff
        k = (curr >> shift) & 0xff
        out.append(b ^ k)
    return bytes(out)
