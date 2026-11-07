# -*- coding: utf-8 -*-
"""OmniReverse Emulator Engine (emulator_engine.py)
Provides CPU emulation and execution tracing via Unicorn Engine 2.1 with
bounded image mapping (CWE-789) and zero-detail Capstone fast disassembly.
"""

from __future__ import annotations

import os
from typing import Any

from omni_config import safe_read_binary

try:
    import pefile
except ImportError:
    pefile = None

try:
    import capstone
except ImportError:
    capstone = None

try:
    import unicorn
    from unicorn import x86_const
except ImportError:
    unicorn = None

MAX_EMULATED_IMAGE_BYTES = 128 * 1024 * 1024


def align_page(val: int, page_size: int = 0x1000) -> int:
    return (val + (page_size - 1)) & ~(page_size - 1)


def emulate_pe_range(
    pe_path: str,
    start_va: int,
    end_va: int,
    max_instructions: int = 10000,
    arch: str = "x64",
    capture_cmps: bool = True,
    raw_data: bytes | None = None,
) -> dict[str, Any]:
    """Emulates a specific address range in a PE binary safely using Unicorn."""
    if not pe_path or not os.path.isfile(pe_path):
        return {"error": f"Hedef dosya bulunamadi: {pe_path}"}

    if not unicorn or not capstone or not pefile:
        return {"error": "Gerekli kutuphaneler (unicorn, capstone, pefile) eksik."}

    max_instructions = max(1, min(int(max_instructions), 50000))
    pe = None
    try:
        data = raw_data if raw_data is not None else safe_read_binary(pe_path)
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        is_64 = (pe.FILE_HEADER.Machine == 0x8664) or (arch.lower() == "x64")
        uc_mode = unicorn.UC_MODE_64 if is_64 else unicorn.UC_MODE_32
        cs_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32

        uc = unicorn.Uc(unicorn.UC_ARCH_X86, uc_mode)
        cs = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        cs.detail = False

        max_sec_end = align_page(pe.OPTIONAL_HEADER.SizeOfImage)
        for s in pe.sections:
            raw_chunk = s.get_data()
            sec_span = s.VirtualAddress + max(s.Misc_VirtualSize, len(raw_chunk) if raw_chunk else 0)
            max_sec_end = max(max_sec_end, align_page(sec_span))

        if max_sec_end <= 0 or max_sec_end > MAX_EMULATED_IMAGE_BYTES:
            return {"error": f"PE goruntu boyutu emulasyon guvenlik sinirini asiyor ({max_sec_end} bayt)."}

        uc.mem_map(image_base, max_sec_end)

        headers_size = min(len(data), pe.OPTIONAL_HEADER.SizeOfHeaders, max_sec_end)
        if headers_size > 0:
            uc.mem_write(image_base, data[:headers_size])

        for s in pe.sections:
            sec_va = image_base + s.VirtualAddress
            raw_chunk = s.get_data()
            if raw_chunk and s.VirtualAddress + len(raw_chunk) <= max_sec_end:
                uc.mem_write(sec_va, raw_chunk)

        stack_base = 0x700000000000 if is_64 else 0x70000000
        stack_size = 2 * 1024 * 1024
        uc.mem_map(stack_base, stack_size)
        sp_init = stack_base + stack_size - 0x1000

        if is_64:
            uc.reg_write(x86_const.UC_X86_REG_RSP, sp_init)
            uc.reg_write(x86_const.UC_X86_REG_RBP, sp_init)
            uc.reg_write(x86_const.UC_X86_REG_RIP, start_va)
        else:
            uc.reg_write(x86_const.UC_X86_REG_ESP, sp_init)
            uc.reg_write(x86_const.UC_X86_REG_EBP, sp_init)
            uc.reg_write(x86_const.UC_X86_REG_EIP, start_va)

        traced_instructions: list[str] = []
        captured_comparisons: list[dict[str, str]] = []
        recovered_chars: list[str] = []
        instructions_executed = 0
        auto_mapped_pages = 0

        def hook_mem_invalid(uc_inst, access, address, size, value, user_data):
            nonlocal auto_mapped_pages
            if auto_mapped_pages >= 64:
                return False
            page_addr = address & ~0xFFF
            try:
                uc_inst.mem_map(page_addr, 0x1000)
                auto_mapped_pages += 1
                return True
            except Exception:
                return False

        uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        def hook_code(uc_inst, address, size, user_data):
            nonlocal instructions_executed
            instructions_executed += 1
            if instructions_executed > max_instructions:
                uc_inst.emu_stop()
                return

            if not capture_cmps and len(traced_instructions) >= 50:
                return

            try:
                code_bytes = bytes(uc_inst.mem_read(address, min(max(size, 1), 16)))
                for insn in cs.disasm(code_bytes, address):
                    mnemonic = insn.mnemonic.lower()
                    op_str = insn.op_str
                    if capture_cmps and mnemonic in ("cmp", "test", "xor"):
                        reg_val_str = ""
                        if is_64:
                            rax = uc_inst.reg_read(x86_const.UC_X86_REG_RAX)
                            rcx = uc_inst.reg_read(x86_const.UC_X86_REG_RCX)
                            rdx = uc_inst.reg_read(x86_const.UC_X86_REG_RDX)
                            rbx = uc_inst.reg_read(x86_const.UC_X86_REG_RBX)
                            for bval in (rax & 0xFF, rbx & 0xFF, rcx & 0xFF, rdx & 0xFF):
                                if 0x20 <= bval <= 0x7E:
                                    ch = chr(bval)
                                    if ch not in recovered_chars[-3:]:
                                        recovered_chars.append(ch)
                            reg_val_str = f"RAX=0x{rax:X}, RCX=0x{rcx:X}, RDX=0x{rdx:X}, RBX=0x{rbx:X}"
                        if len(captured_comparisons) < 100:
                            captured_comparisons.append({
                                "address": f"0x{address:X}",
                                "asm": f"{mnemonic} {op_str}",
                                "registers": reg_val_str,
                            })
                    if len(traced_instructions) < 50:
                        traced_instructions.append(f"0x{address:X}:  {mnemonic} {op_str}")
                    break
            except Exception:
                pass

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

        try:
            uc.emu_start(start_va, end_va, timeout=5_000_000, count=max_instructions)
        except unicorn.UcError as err:
            emu_status = f"Durdu: {err}"
        else:
            emu_status = "Aralik basariyla tamamlandi"

        return {
            "target": os.path.basename(pe_path),
            "start_va": hex(start_va),
            "end_va": hex(end_va),
            "instructions_executed": instructions_executed,
            "status": emu_status,
            "recovered_keystream_chars": "".join(recovered_chars[:100]),
            "comparisons_count": len(captured_comparisons),
            "comparisons_sample": captured_comparisons[:20],
            "trace_sample": traced_instructions[:20],
        }
    except Exception as e:
        return {"error": f"Emulasyon calisma hatasi: {str(e)}"}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass
