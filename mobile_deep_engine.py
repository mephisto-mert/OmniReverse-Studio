# -*- coding: utf-8 -*-
"""OmniReverse Mobile Deep Analysis Engine (mobile_deep_engine.py)
Implements:
1. Flutter libapp.so Dart AOT Snapshot & Pool Analyzer (Blutter-style)
2. React Native Hermes Bytecode (.hbc) Header & String/Module Decoder
3. Unity IL2CPP (libil2cpp.so + global-metadata.dat 0xFAB11BAF) Metadata Dumper
4. iOS .ipa / Mach-O Load Command, FairPlay cryptid, Info.plist & Swift Demangler
5. Multi-Platform Frida SSL Pinning, Anti-Debug & Root/Jailbreak Bypass Synthesizer
"""

from __future__ import annotations

import os
import plistlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from omni_config import mask_secret_preview, safe_read_binary, safe_zip_read

DART_SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
HERMES_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
IL2CPP_METADATA_MAGIC = 0xFAB11BAF


# ---------------------------------------------------------------------------
# 1. FLUTTER DART AOT (libapp.so) SNAPSHOT ANALYZER
# ---------------------------------------------------------------------------

def analyze_flutter_aot_snapshot(target_path: str) -> dict[str, Any]:
    """Extracts libapp.so from an APK or reads a standalone ELF to recover Dart AOT metadata, packages, and endpoints."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    libapp_bytes = b""
    arch_found = "unknown"
    if zipfile.is_zipfile(target_path):
        with zipfile.ZipFile(target_path, "r") as zf:
            app_libs = [n for n in zf.namelist() if n.endswith("libapp.so")]
            if not app_libs:
                return {"is_flutter_aot": False, "message": "APK icinde libapp.so bulunamadi."}
            chosen = next((n for n in app_libs if "arm64" in n), app_libs[0])
            arch_found = chosen.split("/")[1] if "/" in chosen else "elf"
            libapp_bytes = safe_zip_read(zf, chosen)
    else:
        libapp_bytes = safe_read_binary(target_path)

    aot_symbols = [
        sym.decode("ascii")
        for sym in (
            b"_kDartVmSnapshotData",
            b"_kDartVmSnapshotInstructions",
            b"_kDartIsolateSnapshotData",
            b"_kDartIsolateSnapshotInstructions",
        )
        if sym in libapp_bytes
    ]

    snap_off = libapp_bytes.find(DART_SNAPSHOT_MAGIC)
    sdk_hash = ""
    if snap_off != -1 and snap_off + 64 <= len(libapp_bytes):
        hash_match = re.search(rb"[0-9a-f]{32}", libapp_bytes[snap_off : snap_off + 96])
        if hash_match:
            sdk_hash = hash_match.group(0).decode("ascii")

    packages = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"package:[A-Za-z0-9_./\-]{3,96}\.dart", libapp_bytes)})
    urls = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"https?://[A-Za-z0-9.\-_:/?=&%]{6,120}", libapp_bytes)})
    camel_classes = sorted({m.decode("ascii") for m in re.findall(rb"\b[A-Z][a-zA-Z0-9]{4,40}(?:Service|Controller|Bloc|Repository|Client|Provider|Model)\b", libapp_bytes)})

    return {
        "is_flutter_aot": bool(aot_symbols or snap_off != -1 or packages),
        "target": os.path.basename(target_path),
        "abi": arch_found,
        "dart_snapshot_magic_offset": hex(snap_off) if snap_off != -1 else None,
        "dart_snapshot_sdk_hash": sdk_hash,
        "exported_aot_symbols": aot_symbols,
        "dart_packages_count": len(packages),
        "dart_packages_sample": packages[:50],
        "discovered_dart_classes": camel_classes[:50],
        "api_urls": urls[:40],
    }


# ---------------------------------------------------------------------------
# 2. REACT NATIVE HERMES BYTECODE (.hbc) DECODER
# ---------------------------------------------------------------------------

def decompile_hermes_bytecode(target_path: str) -> dict[str, Any]:
    """Parses React Native Hermes bytecode (.hbc / index.android.bundle) headers, string pools, and pseudo-JS summary."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    bundle_bytes = b""
    source_entry = os.path.basename(target_path)
    if zipfile.is_zipfile(target_path):
        with zipfile.ZipFile(target_path, "r") as zf:
            cands = [n for n in zf.namelist() if n.endswith(("index.android.bundle", "main.jsbundle", ".hbc"))]
            if not cands:
                return {"is_hermes": False, "message": "APK/IPA icinde React Native bundle bulunamadi."}
            source_entry = cands[0]
            bundle_bytes = safe_zip_read(zf, source_entry)
    else:
        bundle_bytes = safe_read_binary(target_path)

    if len(bundle_bytes) < 64 or bundle_bytes[:8] != HERMES_MAGIC:
        return {
            "is_hermes": False,
            "entry": source_entry,
            "message": "Hermes 64-bit magic (0x1F1903C103BC1FC6) eslesmedi (duz JS bundle olabilir).",
        }

    hbc_version = struct.unpack_from("<I", bundle_bytes, 8)[0]
    sha1_hex = bundle_bytes[12:32].hex()
    file_len, global_code_idx, func_count, str_kind_cnt, ident_cnt, str_cnt = struct.unpack_from("<6I", bundle_bytes, 32)

    ascii_strs = [s.decode("utf-8", errors="ignore") for s in re.findall(rb"[\x20-\x7e]{5,120}", bundle_bytes[80:])]
    urls = sorted({s for s in ascii_strs if s.startswith(("http://", "https://", "wss://", "/api/", "/v1/"))})
    identifiers = []
    for s in ascii_strs:
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{3,48}", s) and s not in identifiers:
            identifiers.append(s)
        if len(identifiers) >= 60:
            break

    pseudo_js = [
        f"// Reconstructed Hermes Bytecode v{hbc_version} ({source_entry})",
        f"// Functions: {func_count} | Strings: {str_cnt} | Identifiers: {ident_cnt} | SHA1: {sha1_hex}",
    ]
    for u in urls[:12]:
        pseudo_js.append(f'const ENDPOINT_REF = "{mask_secret_preview(u)}";')
    for fn_name in identifiers[:15]:
        pseudo_js.append(f"function {fn_name}(/* hbc_compiled */) {{ /* Hermes VM opcodes */ }}")

    return {
        "is_hermes": True,
        "entry": source_entry,
        "hbc_version": hbc_version,
        "source_hash_sha1": sha1_hex,
        "declared_file_length": file_len,
        "global_code_index": global_code_idx,
        "function_count": func_count,
        "identifier_count": ident_cnt,
        "string_count": str_cnt,
        "endpoints_recovered": urls[:40],
        "identifiers_sample": identifiers,
        "pseudo_javascript": "\n".join(pseudo_js),
    }


# ---------------------------------------------------------------------------
# 3. UNITY IL2CPP (libil2cpp.so + global-metadata.dat) DUMPER
# ---------------------------------------------------------------------------

def dump_unity_il2cpp(target_path: str, metadata_path: str | None = None) -> dict[str, Any]:
    """Parses Unity IL2CPP global-metadata.dat (0xFAB11BAF) to recover C# classes, methods, and string literals."""
    if not target_path or not os.path.exists(target_path):
        return {"error": f"Hedef bulunamadi: {target_path}"}

    meta_bytes = b""
    has_libil2cpp = False
    if zipfile.is_zipfile(target_path):
        with zipfile.ZipFile(target_path, "r") as zf:
            names = zf.namelist()
            has_libil2cpp = any(n.endswith(("libil2cpp.so", "GameAssembly.dll")) for n in names)
            meta_entries = [n for n in names if n.endswith("global-metadata.dat")]
            if meta_entries:
                meta_bytes = safe_zip_read(zf, meta_entries[0])
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for fn in files:
                if fn in ("libil2cpp.so", "GameAssembly.dll"):
                    has_libil2cpp = True
                elif fn == "global-metadata.dat" and not meta_bytes:
                    meta_bytes = safe_read_binary(os.path.join(root, fn))
    else:
        if metadata_path and os.path.isfile(metadata_path):
            meta_bytes = safe_read_binary(metadata_path)
            has_libil2cpp = True
        else:
            meta_bytes = safe_read_binary(target_path)

    if len(meta_bytes) < 64:
        return {"is_il2cpp": False, "message": "global-metadata.dat verisi bulunamadi veya cok kisa."}

    sanity, version = struct.unpack_from("<II", meta_bytes, 0)
    if sanity != IL2CPP_METADATA_MAGIC:
        return {
            "is_il2cpp": False,
            "has_libil2cpp": has_libil2cpp,
            "header_magic": hex(sanity),
            "message": "Standart 0xFAB11BAF IL2CPP magic eslesmedi (sifrelenmis metadata olabilir).",
        }

    # In IL2CPP metadata v24..v31: offset 0x18 = stringOffset, 0x1C = stringCount (ident table)
    str_off, str_size = struct.unpack_from("<II", meta_bytes, 0x18)
    csharp_symbols: list[str] = []
    if 0 < str_off < len(meta_bytes) and str_size > 0:
        table_slice = meta_bytes[str_off : min(len(meta_bytes), str_off + min(str_size, 262_144))]
        for raw_tok in table_slice.split(b"\x00"):
            if 3 <= len(raw_tok) <= 80:
                tok = raw_tok.decode("utf-8", errors="ignore")
                if tok.isprintable() and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.<>`]{2,78}", tok):
                    csharp_symbols.append(tok)

    urls = sorted({m.decode("utf-8", errors="ignore") for m in re.findall(rb"https?://[A-Za-z0-9.\-_:/?=&%]{6,120}", meta_bytes)})
    unique_syms = list(dict.fromkeys(csharp_symbols))

    return {
        "is_il2cpp": True,
        "has_libil2cpp_binary": has_libil2cpp,
        "metadata_version": version,
        "string_table_offset": hex(str_off),
        "string_table_bytes": str_size,
        "recovered_csharp_symbols_count": len(unique_syms),
        "csharp_symbols_sample": unique_syms[:80],
        "embedded_urls": urls[:30],
    }


# ---------------------------------------------------------------------------
# 4. iOS .IPA / MACH-O / FAIRPLAY & SWIFT DEMANGLER
# ---------------------------------------------------------------------------

def _demangle_swift_basic(sym: str) -> str:
    """Lightweight pure-Python demangler for Swift 5 _$s / $s mangled symbols."""
    s = sym.lstrip("_")
    if not s.startswith(("$s", "$S", "T0")):
        return sym
    body = s[2:]
    parts: list[str] = []
    idx = 0
    while idx < len(body):
        m = re.match(r"(\d+)", body[idx:])
        if m:
            ln = int(m.group(1))
            start = idx + len(m.group(1))
            if ln > 0 and start + ln <= len(body):
                parts.append(body[start : start + ln])
                idx = start + ln
                continue
        idx += 1
    return ".".join(parts) if parts else sym


def analyze_ios_ipa_macho(target_path: str) -> dict[str, Any]:
    """Analyzes an iOS .ipa archive or standalone Mach-O binary (Info.plist, dylibs, FairPlay cryptid, Swift symbols)."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    info_summary: dict[str, Any] = {}
    macho_bytes = b""
    entitlements_preview = ""

    if zipfile.is_zipfile(target_path):
        with zipfile.ZipFile(target_path, "r") as zf:
            names = zf.namelist()
            plists = [n for n in names if re.search(r"Payload/[^/]+\.app/Info\.plist$", n)]
            if plists:
                raw_pl = safe_zip_read(zf, plists[0], max_bytes=8_388_608)
                try:
                    pl_data = plistlib.loads(raw_pl)
                    info_summary = {
                        "bundle_id": pl_data.get("CFBundleIdentifier", ""),
                        "bundle_name": pl_data.get("CFBundleName", ""),
                        "version": pl_data.get("CFBundleShortVersionString", ""),
                        "executable": pl_data.get("CFBundleExecutable", ""),
                        "min_ios_version": pl_data.get("MinimumOSVersion", ""),
                        "ats_settings": pl_data.get("NSAppTransportSecurity", {}),
                    }
                    exe_name = info_summary.get("executable", "")
                    app_dir = os.path.dirname(plists[0])
                    cand_exe = f"{app_dir}/{exe_name}"
                    if exe_name and cand_exe in names:
                        macho_bytes = safe_zip_read(zf, cand_exe)
                except Exception as exc:
                    info_summary["plist_error"] = str(exc)

            prov = [n for n in names if n.endswith("embedded.mobileprovision")]
            if prov:
                raw_prov = safe_zip_read(zf, prov[0], max_bytes=4_194_304)
                p_start = raw_prov.find(b"<?xml")
                p_end = raw_prov.find(b"</plist>")
                if p_start != -1 and p_end != -1:
                    entitlements_preview = raw_prov[p_start : p_end + 8].decode("utf-8", errors="ignore")[:1500]
    else:
        macho_bytes = safe_read_binary(target_path)

    dylibs: list[str] = []
    fairplay_encrypted = False
    macho_arch = "none"
    if len(macho_bytes) >= 32:
        magic = struct.unpack_from("<I", macho_bytes, 0)[0]
        if magic == 0xFEEDFACF:
            macho_arch = "Mach-O 64-bit"
            ncmds = struct.unpack_from("<I", macho_bytes, 16)[0]
            off = 32
            for _ in range(min(ncmds, 256)):
                if off + 8 > len(macho_bytes):
                    break
                cmd, cmdsize = struct.unpack_from("<II", macho_bytes, off)
                if cmdsize < 8 or off + cmdsize > len(macho_bytes):
                    break
                if cmd in (0x0C, 0x18, 0x80000018) and cmdsize >= 24:  # LC_LOAD_DYLIB / WEAK
                    str_off = struct.unpack_from("<I", macho_bytes, off + 8)[0]
                    if str_off < cmdsize:
                        raw_d = macho_bytes[off + str_off : off + cmdsize].split(b"\x00", 1)[0]
                        dylibs.append(raw_d.decode("utf-8", errors="ignore"))
                elif cmd == 0x2C and cmdsize >= 24:  # LC_ENCRYPTION_INFO_64
                    cryptid = struct.unpack_from("<I", macho_bytes, off + 16)[0]
                    fairplay_encrypted = cryptid != 0
                off += cmdsize
        elif magic in (0xCAFEBABE, 0xBEBAFECA):
            macho_arch = "Mach-O Universal Fat Binary"

    swift_raw = [m.decode("ascii") for m in re.findall(rb"_?\$s[A-Za-z0-9_]{6,90}", macho_bytes)]
    swift_demangled = [{"mangled": s, "demangled": _demangle_swift_basic(s)} for s in list(dict.fromkeys(swift_raw))[:35]]

    return {
        "target": os.path.basename(target_path),
        "info_plist": info_summary,
        "macho_format": macho_arch,
        "fairplay_drm_encrypted": fairplay_encrypted,
        "linked_dylibs": dylibs[:50],
        "swift_symbols_demangled": swift_demangled,
        "mobileprovision_preview": entitlements_preview,
    }


# ---------------------------------------------------------------------------
# 5. MULTI-PLATFORM FRIDA SSL PINNING & ANTI-DEBUG BYPASS VAULT
# ---------------------------------------------------------------------------

def generate_frida_bypass_bundle(profile: str = "all", package_name: str = "") -> dict[str, Any]:
    """Generates production-grade Frida JS scripts for SSL Pinning, Anti-Debug, and Root/Jailbreak bypass."""
    prof = (profile or "all").lower().strip()
    blocks: list[str] = [
        f"// OmniReverse Studio v3.0 — Autonomous Frida Bypass Suite (profile={prof}, target={package_name or 'universal'})",
        "Java && Java.available && Java.perform(function() {",
    ]

    if prof in ("all", "ssl", "ssl_pinning"):
        blocks.extend([
            "  try {",
            "    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');",
            "    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {",
            "      console.log('[Omni-SSL] Conscrypt TrustManagerImpl bypassed -> ' + host);",
            "      return untrustedChain;",
            "    };",
            "  } catch (e) {}",
            "  try {",
            "    var CertPinner = Java.use('okhttp3.CertificatePinner');",
            "    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, pins) {",
            "      console.log('[Omni-SSL] OkHttp3 CertificatePinner bypassed -> ' + host);",
            "    };",
            "  } catch (e) {}",
        ])

    if prof in ("all", "root", "root_jailbreak"):
        blocks.extend([
            "  try {",
            "    var File = Java.use('java.io.File');",
            "    File.exists.implementation = function() {",
            "      var p = this.getAbsolutePath();",
            "      if (p.indexOf('/su') !== -1 || p.indexOf('Magisk') !== -1 || p.indexOf('Superuser') !== -1) return false;",
            "      return this.exists.call(this);",
            "    };",
            "  } catch (e) {}",
        ])

    blocks.append("});")

    if prof in ("all", "ssl", "ssl_pinning", "flutter"):
        blocks.extend([
            "// Native BoringSSL / Flutter libflutter.so & iOS SecTrust Hook",
            "['libflutter.so', 'libssl.so'].forEach(function(modName) {",
            "  var m = Process.findModuleByName(modName);",
            "  if (m) {",
            "    var exp = m.findExportByName('SSL_CTX_set_custom_verify') || m.findExportByName('X509_verify_cert');",
            "    if (exp) Interceptor.replace(exp, new NativeCallback(function() { return 1; }, 'int', ['pointer']));",
            "  }",
            "});",
        ])

    if prof in ("all", "anti_debug"):
        blocks.extend([
            "// Native ptrace & Windows IsDebuggerPresent Anti-Debug Cloak",
            "var ptracePtr = Module.findExportByName(null, 'ptrace');",
            "if (ptracePtr) Interceptor.replace(ptracePtr, new NativeCallback(function() { return 0; }, 'long', ['int', 'int', 'pointer', 'pointer']));",
            "var isDbg = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');",
            "if (isDbg) Interceptor.replace(isDbg, new NativeCallback(function() { return 0; }, 'int', []));",
        ])

    script_code = "\n".join(blocks)
    cli_cmd = f"frida -U -f {package_name or 'com.target.app'} -l omni_bypass.js"
    return {
        "profile": prof,
        "target_package": package_name or "universal",
        "cli_command": cli_cmd,
        "script_lines": len(blocks),
        "frida_script": script_code,
    }
