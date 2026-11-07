# -*- coding: utf-8 -*-
"""OmniReverse PE Rebuilder Engine (rebuilder_engine.py)
Reconstructs unpacked PE binaries, updates Entry Point (OEP),
repairs section headers safely, scans anti-dump honeypots, and exports clean PE files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from omni_config import safe_read_binary

try:
    import pefile
except ImportError:
    pefile = None


def rebuild_pe_file(
    input_pe: str,
    output_pe: str,
    new_oep_va_or_rva: int,
    decrypted_sections_data: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Rebuilds a PE binary with a validated OEP and optional decrypted section payloads."""
    if not input_pe or not os.path.isfile(input_pe):
        return {"error": f"Girdi dosyasi bulunamadi: {input_pe}"}
    if not output_pe:
        return {"error": "Cikti dosya yolu belirtilmedi."}
    if Path(input_pe).resolve() == Path(output_pe).resolve():
        return {"error": "Guvenlik engeli: Cikti dosyasi girdi dosyasi ile ayni olamaz (yerinde yazma engellendi)."}

    if not pefile:
        return {"error": "pefile kutuphanesi yuklu degil."}

    pe = None
    try:
        raw_bytes = safe_read_binary(input_pe)
        pe = pefile.PE(data=raw_bytes)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        oep_rva = int(new_oep_va_or_rva)
        if oep_rva >= image_base:
            oep_rva = oep_rva - image_base

        if oep_rva < 0 or oep_rva > 0xFFFFFFFF:
            return {"error": f"Gecersiz OEP RVA degeri (32-bit sinirlari disinda): {hex(oep_rva)}"}

        old_ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep_rva

        sections_updated = []
        if decrypted_sections_data:
            for s in pe.sections:
                sname = s.Name.decode("latin1", errors="ignore").strip("\x00")
                if sname in decrypted_sections_data:
                    new_bytes = decrypted_sections_data[sname]
                    # Preserve readable/executable flags without forcing writable RWX unless already writable
                    s.Characteristics |= 0x20000000 | 0x40000000  # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
                    pe.set_bytes_at_offset(s.PointerToRawData, new_bytes[: s.SizeOfRawData])
                    sections_updated.append(sname)

        Path(output_pe).parent.mkdir(parents=True, exist_ok=True)
        pe.write(output_pe)

        return {
            "status": "success",
            "output_file": os.path.abspath(output_pe),
            "old_entry_point": hex(old_ep),
            "new_entry_point_rva": hex(oep_rva),
            "new_entry_point_va": hex(image_base + oep_rva),
            "sections_updated": sections_updated,
        }
    except Exception as e:
        return {"error": f"PE Rebuild hatasi: {str(e)}"}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def scan_anti_dump_honeypots(pe_path: str) -> dict[str, Any]:
    """Detects anti-dump traps, fake entry points, and honeypot functions in a PE binary."""
    if not pe_path or not os.path.isfile(pe_path):
        return {"error": f"Dosya bulunamadi: {pe_path}"}

    try:
        data = safe_read_binary(pe_path)
        trap_keywords = [
            b"dumpladin", b"dumped", b"honeypot", b"trap", b"fake",
            b"debugger", b"caught", b"cheater", b"antidump",
        ]

        detected_traps = []
        for kw in trap_keywords:
            idx = 0
            while len(detected_traps) < 50:
                idx = data.find(kw, idx)
                if idx == -1:
                    break
                snippet = data[max(0, idx - 16) : min(len(data), idx + 32)]
                detected_traps.append({
                    "offset": hex(idx),
                    "keyword": kw.decode("latin1"),
                    "raw_snippet": snippet.decode("latin1", errors="ignore"),
                })
                idx += len(kw)

        return {
            "target": os.path.basename(pe_path),
            "traps_found_count": len(detected_traps),
            "traps": detected_traps[:15],
        }
    except Exception as e:
        return {"error": f"Honeypot tarama hatasi: {str(e)}"}
