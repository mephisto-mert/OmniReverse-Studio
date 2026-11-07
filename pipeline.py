"""OmniReverse Engine - Unified Reverse Engineering & Deobfuscation Pipeline.

Coordinates:
- Stage 1: Nyx Protector Detection & Entropy Triage
- Stage 2: AST & Control-Flow Deobfuscation (Lua, JS, Python)
- Stage 3: Binary Unpacking & IAT Reconstruction (.NET, PE, DLL)
- Stage 4: Native Deep Disassembly & APK Decompilation (Ghidra, JADX, WABT)
- Stage 5: Artifact Export & Executive Markdown Synthesis
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import re
from omni_config import (
    STUDIO_ROOT,
    safe_read_binary,
    sanitize_relative_filename,
    find_ghidra_headless,
    find_jadx_executable,
    find_wabt_tool,
)

# Optional external Nyx engine path via environment variable (safe append, never hijacks sys.path[0])
_ENV_NYX_DIR = os.environ.get("OMNI_NYX_DIR", "").strip()
if _ENV_NYX_DIR and os.path.isdir(_ENV_NYX_DIR) and _ENV_NYX_DIR not in sys.path:
    sys.path.append(_ENV_NYX_DIR)

try:
    from deob.api import Options, analyze_bytes
    from deob.common import extract_strings, meaningful_strings, printable_ratio, to_text, entropy
    from deob.crypto_detect import scan_crypto_signatures
    from deob.detect import detect
    from deob.luac_disasm import disassemble_luac
    from deob.pe_parser import PEParser
    from deob.smart_extractor import export_all_artifacts
    HAS_NYX_DEOB = True
except ImportError:
    import math
    from collections import Counter
    HAS_NYX_DEOB = False

    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        sample = data[:2_097_152]
        counts = Counter(sample)
        n = len(sample)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @dataclass
    class Options:
        beautify: bool = True
        aggressive: bool = True
        max_layers: int = 5

    @dataclass
    class _DetResult:
        kind: str = "binary"
        label: str = "Generic Target"
        confidence: int = 85
        obfuscators: list[str] = field(default_factory=list)
        reasons: list[str] = field(default_factory=list)
        entropy: float = 0.0

    @dataclass
    class _AnalyzeResult:
        output: str = ""
        log: list[str] = field(default_factory=list)
        detection: _DetResult = field(default_factory=_DetResult)

    def detect(path_str: str, raw_data: bytes) -> _DetResult:
        ext = Path(path_str).suffix.lower()
        ent = round(entropy(raw_data), 2)
        head = raw_data[:16]
        obfs: list[str] = []
        reasons: list[str] = []

        if not raw_data:
            return _DetResult(kind="empty", label="Empty File (0 Bytes)", confidence=100, entropy=0.0)

        if head[:2] == b"MZ" or ext in (".exe", ".dll", ".sys"):
            if b".vmp" in raw_data[:65536]:
                obfs.append("VMProtect")
            if b".themida" in raw_data[:65536] or b"WinLicense" in raw_data[:131072]:
                obfs.append("Themida/WinLicense")
            if b"UPX0" in raw_data[:65536] or b"UPX1" in raw_data[:65536]:
                obfs.append("UPX")
            if b"ConfuserEx" in raw_data[:262144]:
                obfs.append("ConfuserEx (.NET)")
            if b"mscoree.dll" in raw_data[:524288]:
                reasons.append(".NET CLR metadata detected")
            return _DetResult(kind="pe", label="Windows PE Binary", confidence=95, obfuscators=obfs, reasons=reasons, entropy=ent)

        if head[:4] == b"\x7fELF" or ext in (".elf", ".so"):
            if b"UPX!" in raw_data[:65536]:
                obfs.append("UPX")
            return _DetResult(kind="elf", label="POSIX ELF Binary", confidence=95, obfuscators=obfs, entropy=ent)

        if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") or ext in (".dylib", ".macho"):
            return _DetResult(kind="macho", label="Apple Mach-O Binary", confidence=95, entropy=ent)

        if head[:4] == b"\x00asm" or ext == ".wasm":
            return _DetResult(kind="wasm", label="WebAssembly Module", confidence=98, entropy=ent)

        if head[:4] == b"PK\x03\x04" and ext in (".apk", ".xapk", ".aab", ".jar"):
            return _DetResult(kind="apk", label="Android APK / Archive", confidence=95, entropy=ent)

        if head[:4] == b"\x1bLua" or ext == ".luac":
            return _DetResult(kind="luac", label="Compiled Lua Bytecode", confidence=95, entropy=ent)

        if ext == ".lua":
            if b"Luraph" in raw_data or b"MoonSec" in raw_data:
                obfs.append("Lua VM Obfuscator")
            return _DetResult(kind="lua", label="Lua Script", confidence=92, obfuscators=obfs, entropy=ent)

        if ext in (".js", ".mjs", ".cjs"):
            if b"_0x" in raw_data[:32768]:
                obfs.append("javascript-obfuscator (_0x array)")
            return _DetResult(kind="js", label="JavaScript Source", confidence=92, obfuscators=obfs, entropy=ent)

        if ext == ".map":
            return _DetResult(kind="sourcemap", label="Web SourceMap JSON", confidence=95, entropy=ent)

        if ext == ".py":
            return _DetResult(kind="py", label="Python Source", confidence=92, entropy=ent)

        if ext in (".cpp", ".c", ".h", ".hpp", ".cc"):
            return _DetResult(kind="cpp", label="C/C++ Source Code", confidence=95, entropy=ent)

        return _DetResult(kind=ext.lstrip(".") or "binary", label=f"File ({ext or 'binary'})", confidence=80, entropy=ent)

    def _deobfuscate_script_text(text: str) -> tuple[str, list[str]]:
        steps: list[str] = []
        out = text

        def _lua_char(m: re.Match) -> str:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            return '"' + "".join(chr(n) for n in nums if 0 <= n < 256) + '"'

        next_out = re.sub(r"string\.char\(([\d,\s]+)\)", _lua_char, out)
        if next_out != out:
            steps.append("[Deob-Script] Resolved Lua string.char(...) byte sequences.")
            out = next_out

        next_out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), out)
        if next_out != out:
            steps.append("[Deob-Script] Decoded hex escape sequences (\\xHH).")
            out = next_out

        def _b64_call(m: re.Match) -> str:
            try:
                raw_b = base64.b64decode(m.group(2), validate=True)
                dec = raw_b.decode("utf-8")
                if all(c.isprintable() or c in "\r\n\t" for c in dec):
                    return repr(dec)
            except Exception:
                pass
            return m.group(0)

        next_out = re.sub(r"\b(atob|b64decode)\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)", _b64_call, out)
        if next_out != out:
            steps.append("[Deob-Script] Decoded inline Base64 literal calls.")
            out = next_out

        return out, steps

    def analyze_bytes(file_name: str, raw_data: bytes, opts: Options) -> _AnalyzeResult:
        det = detect(file_name, raw_data)
        if det.kind in ("pe", "elf", "macho", "wasm", "apk", "luac", "binary", "empty"):
            ascii_hits = re.findall(rb"[\x20-\x7e]{6,96}", raw_data[:262144])
            preview_lines = [f"// Binary Target: {file_name} ({det.label}, {len(raw_data):,} bytes, entropy={det.entropy:.2f})"]
            for s in ascii_hits[:60]:
                preview_lines.append(s.decode("ascii", errors="ignore"))
            return _AnalyzeResult(
                output="\n".join(preview_lines),
                log=["[Static-Binary-Summary] Extracted printable strings without corrupt UTF-8 decoding."],
                detection=det,
            )
        text_in = raw_data.decode("utf-8", errors="replace")
        clean_text, steps = _deobfuscate_script_text(text_in)
        if not steps:
            steps.append("[Static-Script-Analyzer] Completed static source inspection.")
        return _AnalyzeResult(output=clean_text, log=steps, detection=det)

    def scan_crypto_signatures(raw_data: bytes, log: list[str]) -> list[dict[str, Any]]:
        from triage_engine import detect_crypto
        res = detect_crypto(raw_data)
        return res.get("signatures", [])

    class PEParser:
        def __init__(self, raw_data: bytes):
            self.raw_data = raw_data

        def parse(self):
            @dataclass
            class _PEInfo:
                valid: bool = False
                machine_str: str = "unknown"
                entry_point: int = 0
                image_base: int = 0
                packer: str = ""
                has_hollowed_sections: bool = False

            info = _PEInfo(valid=False)
            if len(self.raw_data) < 64 or self.raw_data[:2] != b"MZ":
                return info
            try:
                import pefile
                pe = pefile.PE(data=self.raw_data, fast_load=True)
                try:
                    info.valid = True
                    mach = pe.FILE_HEADER.Machine
                    info.machine_str = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64"}.get(mach, hex(mach))
                    info.entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                    info.image_base = int(pe.OPTIONAL_HEADER.ImageBase)
                    for sec in pe.sections:
                        sname = sec.Name.decode("latin1", errors="ignore").strip("\x00")
                        sname_low = sname.lower()
                        if ".vmp" in sname_low and not info.packer:
                            info.packer = "VMProtect"
                        elif (".themida" in sname_low or ".winlice" in sname_low) and not info.packer:
                            info.packer = "Themida/WinLicense"
                        elif "upx" in sname_low and not info.packer:
                            info.packer = "UPX"
                        if sname in (".text", ".data", ".rdata") and sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                            info.has_hollowed_sections = True
                finally:
                    pe.close()
            except Exception:
                info.valid = False
            return info

    def export_all_artifacts(
        target_name: str,
        raw_data: bytes,
        decompiled_output: str,
        log_lines: list[str],
        pe_info: Any,
        output_base_dir: str,
    ) -> str:
        safe_stem = sanitize_relative_filename(Path(target_name).stem or "target").replace("/", "_").replace("\\", "_")
        safe_name = sanitize_relative_filename(Path(target_name).name or "target.bin").replace("/", "_").replace("\\", "_")
        out_d = Path(output_base_dir).resolve() / f"omni_export_{safe_stem}"
        out_d.mkdir(parents=True, exist_ok=True)
        if decompiled_output:
            (out_d / f"{safe_name}.decompiled.txt").write_text(
                decompiled_output[:200000], encoding="utf-8", errors="replace"
            )
        return str(out_d)

GHIDRA_PATH = Path(find_ghidra_headless() or "") if find_ghidra_headless() else Path()
JADX_EXE = find_jadx_executable()
WABT_WASM2WAT = find_wabt_tool("wasm2wat")


@dataclass
class OmniReport:
    target_name: str
    target_path: str
    file_size: int
    sha256: str
    kind: str
    label: str
    confidence: int
    obfuscators: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    crypto_hits: list[dict[str, Any]] = field(default_factory=list)
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    indicators: dict[str, Any] = field(default_factory=dict)
    native_tls_audit: dict[str, Any] = field(default_factory=dict)
    entropy: float = 0.0
    is_packed: bool = False
    decompiled_source: str = ""
    export_directory: str = ""
    pipeline_log: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "size": self.file_size,
            "sha256": self.sha256,
            "kind": self.kind,
            "label": self.label,
            "obfuscators": self.obfuscators,
            "reasons": self.reasons,
            "crypto_hits": self.crypto_hits,
            "capabilities": self.capabilities,
            "indicators": self.indicators,
            "native_tls_audit": self.native_tls_audit,
            "entropy": self.entropy,
            "is_packed": self.is_packed,
            "export_dir": self.export_directory,
            "log": self.pipeline_log,
            "error": self.error or None,
            "preview": "\n".join(self.decompiled_source.splitlines()[:100])
        }

    def to_markdown(self) -> str:
        lines = [
            f"# ⚡ OmniReverse Pipeline Report: {self.target_name}",
            "",
            "## 1. Hedef ve Dosya Kimliği",
            f"* **Dosya:** `{self.target_name}` ({self.file_size:,} bayt)",
            f"* **SHA-256:** `{self.sha256}`",
            f"* **Tür:** {self.label} (`{self.kind}` - %{self.confidence} Güven)",
            f"* **Genel Entropi:** `{self.entropy:.2f}` ({'⚠️ Yüksek / Paketlenmiş' if self.entropy > 7.0 else 'Normal'})",
            "",
            "## 2. Koruma ve Şifreleme Tespiti (Nyx Triage)",
        ]

        if self.obfuscators:
            lines.append(f"* **Tespit Edilen Koruyucular:** **{', '.join(self.obfuscators)}**")
        else:
            lines.append("* **Tespit Edilen Koruyucu:** Bilinen ticari koruma imzası bulunamadı.")

        if self.crypto_hits:
            lines.append(f"* **Kriptografik Sabitler ({len(self.crypto_hits)} adet):**")
            for hit in self.crypto_hits[:8]:
                lines.append(f"  - `{hit.get('algo')}` ({hit.get('type', 'Sabit')})")

        if self.capabilities:
            lines.append(f"* **Davranış ve Tehdit Göstergeleri (Capabilities):**")
            for cap in self.capabilities[:5]:
                evs = ", ".join(h.get("evidence", "") for h in cap.get("hits", [])[:3])
                lines.append(f"  - `[{cap['severity'].upper()}]` {cap['label']}: {evs}")

        if self.indicators and "counts" in self.indicators:
            lines.append(f"* **Statik Göstergeler (IoC Summary):** {self.indicators['counts']}")

        lines.extend([
            "",
            "## 3. Boru Hattı İşlem Günlüğü (Pipeline Steps)",
        ])
        for entry in self.pipeline_log:
            lines.append(f"- {entry}")

        if self.export_directory:
            lines.extend([
                "",
                "## 4. Dışa Aktarılan Dosyalar",
                f"* **Çıktı Klasörü:** `{self.export_directory}`",
            ])

        lines.extend([
            "",
            "## 5. Decompile / Deobfuscate Kod Önizlemesi",
            "```c" if self.kind in ("pe", "dotnet", "binary") else f"```{self.kind}",
            "\n".join(self.decompiled_source.splitlines()[:80]),
            "```",
        ])

        return "\n".join(lines)


def run_pipeline(
    path: str,
    aggressive: bool = True,
    beautify: bool = True,
    export_base: str | None = None,
    allow_live_execution: bool = False,
    export_artifacts: bool = True,
) -> OmniReport:
    """Executes the full multi-stage reverse engineering and deobfuscation pipeline.

    Security Note (CWE-94): Static pipeline NEVER executes target binaries on the host OS
    unless `allow_live_execution=True` is explicitly passed by a dynamic unpacking caller.
    """
    target_path = Path(path).resolve()
    if not target_path.is_file():
        raise FileNotFoundError(f"Target file not found: {target_path}")

    raw_data = safe_read_binary(target_path)
    file_size = len(raw_data)
    file_hash = hashlib.sha256(raw_data).hexdigest()
    file_name = target_path.name

    log: list[str] = [f"[*] Hedef yüklendi: {file_name} ({file_size:,} bayt)"]

    # -------------------------------------------------------------
    # Stage 1: Nyx Triage & Protector Detection
    # -------------------------------------------------------------
    det = detect(str(target_path), raw_data)
    kind = det.kind
    label = det.label
    obfuscators = list(det.obfuscators)
    reasons = list(det.reasons)
    ent = round(det.entropy if hasattr(det, "entropy") else 0.0, 2)
    if ent == 0.0 and raw_data:
        ent = round(entropy(raw_data), 2)

    log.append(f"[Nyx-Triage] Tür: {label}, Entropi: {ent:.2f}, Koruma: {', '.join(obfuscators) if obfuscators else 'Yok'}")

    # Scan crypto constants
    crypto_hits = []
    try:
        crypto_hits = scan_crypto_signatures(raw_data[:500000], log)
        if crypto_hits:
            log.append(f"[Nyx-Crypto] {len(crypto_hits)} kripto imzası tespit edildi.")
    except Exception as exc:
        log.append(f"[Nyx-Crypto-Err] {exc}")

    capabilities = []
    indicators = {}
    try:
        from triage_engine import match_capabilities, extract_indicators
        capabilities = match_capabilities(str(target_path), raw_data)
        indicators = extract_indicators(raw_data)
        if capabilities:
            cap_summary = ", ".join(f"{c['id']}({c['severity']})" for c in capabilities[:3])
            log.append(f"[Triage-Caps] Tehdit profili: {cap_summary}")
    except Exception as exc:
        log.append(f"[Triage-Caps-Err] {exc}")

    # -------------------------------------------------------------
    # Stage 2 & 3: Execution based on Target Type
    # -------------------------------------------------------------
    decompiled_source = ""
    is_packed = bool(obfuscators)
    pe_info = None
    native_tls_audit: dict[str, Any] = {}

    opts = Options(beautify=beautify, aggressive=aggressive, max_layers=5)

    if target_path.suffix.lower() == ".apk" or (raw_data[:4] == b"PK\x03\x04" and "apk" in file_name.lower()):
        log.append("[Pipeline] Android APK paketi tespit edildi, OmniReverse APK Motoru devrede...")
        kind = "apk"
        label = "Android APK Uygulaması"
        from apk_engine import analyze_apk
        apk_res = analyze_apk(target_path, log)
        if apk_res.get("protectors"):
            for prot in apk_res["protectors"]:
                if prot not in obfuscators:
                    obfuscators.append(prot)
                    is_packed = True
        decompiled_source = apk_res.get("extracted_preview", "")

    elif kind == "wasm":
        log.append("[Pipeline] WebAssembly modülü tespit edildi, WABT/Pure-Python WASM motoru devrede...")
        from wasm_engine import inspect_wasm_headers, disassemble_wasm
        hdr = inspect_wasm_headers(str(target_path))
        dis = disassemble_wasm(str(target_path), max_lines=120)
        decompiled_source = dis.get("wat_preview") or json.dumps(hdr, indent=2, ensure_ascii=False)

    elif kind in ("elf", "macho"):
        log.append(f"[Pipeline] Çoklu Platform İkili Dosya motoru devrede ({label})...")
        from granular_engine import inspect_pe_symbols
        sym = inspect_pe_symbols(str(target_path))
        decompiled_source = json.dumps(sym, indent=2, ensure_ascii=False)

    elif kind in ("lua", "js", "py", "pyc", "luac"):
        log.append(f"[Pipeline] Script/Bytecode çözücü motoru devrede ({kind})...")
        res = analyze_bytes(file_name, raw_data, opts)
        decompiled_source = res.output
        log.extend(res.log)
        if res.detection.obfuscators:
            for obf in res.detection.obfuscators:
                if obf not in obfuscators:
                    obfuscators.append(obf)

    elif kind in ("pe", "dotnet") or (kind == "binary" and raw_data[:2] == b"MZ"):
        log.append("[Pipeline] PE / İkili Dosya motoru devrede...")
        has_hollowed_sections = False
        try:
            pe_parser = PEParser(raw_data)
            pe_info = pe_parser.parse()
            if pe_info.valid:
                log.append(f"[PE] Mimari: {pe_info.machine_str}, Giriş Noktası: {hex(pe_info.entry_point)}")
                if pe_info.packer and pe_info.packer not in obfuscators:
                    obfuscators.append(pe_info.packer)
                    is_packed = True
                has_hollowed_sections = bool(getattr(pe_info, "has_hollowed_sections", False))
        except Exception as exc:
            log.append(f"[PE-Err] Ayrıştırma uyarısı: {exc}")

        res = analyze_bytes(file_name, raw_data, opts)
        decompiled_source = res.output
        log.extend(res.log)

        # Stage 3.5: Safe Sandboxed Unicorn CPU Emulation (in-memory only, never executes on host OS)
        if pe_info and getattr(pe_info, "valid", False) and (is_packed or any("Kakura" in o or "VM" in o for o in obfuscators)):
            try:
                from emulator_engine import emulate_pe_range
                log.append("[Unicorn-Emulation] Özel VM/Packer tespit edildi, izole CPU emülasyonu başlatılıyor...")
                img_base = getattr(pe_info, "image_base", 0x140000000) or 0x140000000
                ep = getattr(pe_info, "entry_point", 0x1000) or 0x1000
                emu_start = img_base + ep
                emu_res = emulate_pe_range(str(target_path), start_va=emu_start, end_va=emu_start + 0x4000, max_instructions=5000)
                if emu_res.get("recovered_keystream_chars"):
                    log.append(f"[Unicorn-Emulation] Yakalanan Karşılaştırma / Keystream: {emu_res['recovered_keystream_chars']}")
                log.append(f"[Unicorn-Emulation] {emu_res.get('instructions_executed', 0)} talimat emüle edildi, {emu_res.get('comparisons_count', 0)} karşılaştırma yakalandı.")
            except Exception as e_emu:
                log.append(f"[Unicorn-Emulation] Emülasyon uyarısı: {e_emu}")

        # Stage 3.6: Dynamic Memory Acquisition (STRICTLY OPT-IN via allow_live_execution=True)
        if has_hollowed_sections or any(p in str(obfuscators) for p in ("Themida", "WinLicense", "VMProtect")):
            if allow_live_execution:
                try:
                    from dynamic_unpacker import run_dynamic_memory_unpack
                    log.append("[Dynamic-Unpacker] Canlı bellek unroll ve LCG deobfuscation motoru devrede (allow_live_execution=True)...")
                    dump_res = run_dynamic_memory_unpack(str(target_path), wait_time_sec=2.0)
                    if dump_res.get("status") == "success":
                        log.append(f"[Dynamic-Unpacker] {dump_res.get('total_ram_dumped_mb')} MB bellek döküldü ({dump_res.get('committed_pages_count')} sayfa).")
                        if dump_res.get("gate_prompt_detected"):
                            log.append(f"[Dynamic-Unpacker] Lisans Kapısı Tespit Edildi: {dump_res['gate_prompt_detected']}")
                        for dec_tbl in dump_res.get("lcg_decrypted_tables", []):
                            log.append(f"[LCG-Strings] Çözülen Tablo: {dec_tbl}")
                        if dump_res.get("vm_bytecode_engines"):
                            log.append(f"[VM-Engine] Özel VM Bytecode Motoru ayrıştırıldı: {len(dump_res['vm_bytecode_engines'])} blok bulundu.")
                except Exception as e_dump:
                    log.append(f"[Dynamic-Unpacker] Bellek dökme uyarısı: {e_dump}")
            else:
                log.append("[Dynamic-Unpacker] İçi boşaltılmış/sanallaştırılmış (Hollowed/VMP) bölümler tespit edildi. Güvenli statik analiz korundu (canlı çalıştırma devre dışı).")

        # Stage 3.7: Native TLS, Ed25519 Prologue, 4-Stage Verifier, IAT/Self-CRC & RIP-Relative LEA Branch Audit (single-read cached)
        try:
            from native_tls_hwbp_engine import audit_pe_auth_tls
            native_tls_audit = audit_pe_auth_tls(str(target_path), raw_data=raw_data)
            prol_res = native_tls_audit.get("crypto_prologues") or {}
            if prol_res.get("vmp_protected") and "VMProtect" not in obfuscators:
                obfuscators.append("VMProtect")
                is_packed = True
            if prol_res.get("libsodium_ed25519_prologues"):
                log.append(f"[Native-Crypto] {len(prol_res['libsodium_ed25519_prologues'])} adet libsodium Ed25519 prologu tespit edildi ({prol_res.get('recommended_hook_mode', '')}).")
            if prol_res.get("tls_and_crypto_markers"):
                log.append(f"[Native-TLS] İşaretçiler: {', '.join(prol_res['tls_and_crypto_markers'])}")
            v4 = native_tls_audit.get("verify_detached_4stage") or {}
            if v4.get("priority_2_backward_512b_call_test"):
                log.append(f"[4Stage-Verify] Priority 2 (512B geriye doğru CALL+TEST): {len(v4['priority_2_backward_512b_call_test'])} hedef doğrulama fonksiyonu yakalandı.")
            iat_surf = native_tls_audit.get("iat_and_integrity_surface") or {}
            if iat_surf.get("iat_hookable_slots_count", 0) > 0:
                log.append(f"[IAT-Slots] {iat_surf['iat_hookable_slots_count']} adet kancalanabilir IAT Thunk adresi (FirstThunk) çözümlendi.")
            lea_res = native_tls_audit.get("lea_xrefs") or {}
            if lea_res.get("matches_count", 0) > 0:
                log.append(f"[PE-LEA-XRef] {lea_res['matches_count']} adet hedef string ve RIP-bağıl LEA/Jcc dallanması yakalandı.")
        except Exception as e_tls:
            log.append(f"[Native-TLS-Audit] Uyarı: {e_tls}")

    else:
        res = analyze_bytes(file_name, raw_data, opts)
        decompiled_source = res.output
        log.extend(res.log)
        if target_path.suffix.lower() in (".cpp", ".c", ".h", ".hpp"):
            try:
                from native_tls_hwbp_engine import audit_pe_auth_tls
                native_tls_audit = audit_pe_auth_tls(str(target_path), raw_data=raw_data)
                log.append("[Native-TLS-Source] C/C++ kaynak kodu kripto, Self-CRC, Anti-HWBP ve Timebomb yüzey taraması tamamlandı.")
            except Exception:
                pass

    # -------------------------------------------------------------
    # Stage 4: Artifact Export (safe workspace/temp directory fallback)
    # -------------------------------------------------------------
    export_dir = ""
    if export_artifacts:
        try:
            default_exports = STUDIO_ROOT / ".exports"
            out_base = export_base or str(default_exports)
            export_dir = export_all_artifacts(
                target_name=file_name,
                raw_data=raw_data,
                decompiled_output=decompiled_source,
                log_lines=log,
                pe_info=pe_info,
                output_base_dir=out_base,
            )
            log.append(f"[Export] Tüm analiz ve kod dosyaları paketlendi -> {export_dir}")
        except Exception as exc:
            log.append(f"[Export-Err] Dışa aktarma uyarısı: {exc}")

    return OmniReport(
        target_name=file_name,
        target_path=str(target_path),
        file_size=file_size,
        sha256=file_hash,
        kind=kind,
        label=label,
        confidence=det.confidence if hasattr(det, "confidence") else 85,
        obfuscators=obfuscators,
        reasons=reasons,
        crypto_hits=crypto_hits,
        capabilities=capabilities,
        indicators=indicators,
        native_tls_audit=native_tls_audit,
        entropy=ent,
        is_packed=is_packed,
        decompiled_source=decompiled_source,
        export_directory=export_dir,
        pipeline_log=log,
    )
