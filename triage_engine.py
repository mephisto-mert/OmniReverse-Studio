"""OmniReverse Triage Engine (triage_engine.py)
Provides ultra-lightweight, zero-token-bloat static triage primitives inspired by HexFear:
1. Capabilities & Threat Triaging Matrix (match_capabilities)
2. Cryptographic Constants & Algorithmic Tables Scanner (detect_crypto)
3. Structured IoC & Indicator Harvester (extract_indicators)
4. Targeted Binary Byte Primitives (read_bytes_at, read_at_rva, search_bytes)
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

from omni_config import safe_read_binary

try:
    import pefile
except ImportError:
    pefile = None

# Known Cryptographic Constants
CRYPTO_SIGS = [
    {
        "name": "AES S-box",
        "algo": "AES",
        "bytes": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    },
    {
        "name": "AES inv S-box",
        "algo": "AES",
        "bytes": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
    },
    {
        "name": "SHA-256 init (H0)",
        "algo": "SHA-256",
        "bytes": bytes([0x67, 0xE6, 0x09, 0x6A]),  # 0x6A09E667 LE
    },
    {
        "name": "MD5/SHA-1 init (A)",
        "algo": "MD5 / SHA-1",
        "bytes": bytes([0x01, 0x23, 0x45, 0x67]),  # 0x67452301 LE
    },
    {
        "name": "CRC32 table",
        "algo": "CRC32",
        "bytes": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]),  # 0, 0x77073096 LE
    },
    {
        "name": "SHA-512 init",
        "algo": "SHA-512",
        "bytes": bytes([0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A]),  # 0x6A09E667F3BCC908 LE
    },
    {
        "name": "Base64 alphabet",
        "algo": "Base64",
        "bytes": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    },
    {
        "name": "Base64 URL-safe",
        "algo": "Base64url",
        "bytes": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    },
    {
        "name": "libsodium Ed25519 Verify Prologue (x64)",
        "algo": "Ed25519 (libsodium)",
        "bytes": bytes([0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00]),
    },
    {
        "name": "RFC 8032 Ed25519 Test Vector PubKey",
        "algo": "Ed25519 (RFC8032)",
        "bytes": b"d75a980182b10ab7d54bfed3c964073a",
    },
]

# Capability & Behavior Rules
CAPABILITY_RULES = [
    {
        "id": "network",
        "label": "Network & Telemetry",
        "severity": "info",
        "api": [
            "wsastartup", "socket", "wsasend", "wsarecv", "gethostby", "getaddrinfo",
            "internetopen", "internetconnect", "httpopenrequest", "httpsendrequest",
            "urldownloadtofile", "winhttp", "wsasocket", "inet_addr", "closesocket", "connect"
        ],
        "str": [re.compile(rb"https?://", re.I), re.compile(rb"ftp://", re.I), re.compile(rb"user-agent", re.I), re.compile(rb"POST /"), re.compile(rb"GET /")],
    },
    {
        "id": "crypto",
        "label": "Cryptographic Operations",
        "severity": "info",
        "api": [
            "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptgenkey",
            "crypthashdata", "cryptderivekey", "bcrypt", "ncrypt", "cryptstringto", "cryptprotectdata"
        ],
        "str": [re.compile(rb"\bAES\b"), re.compile(rb"\bRSA\b"), re.compile(rb"\bSHA-?(?:1|256|512)\b", re.I), re.compile(rb"\bMD5\b", re.I), re.compile(rb"base64", re.I)],
    },
    {
        "id": "process_inject",
        "label": "Process Injection & Manipulation",
        "severity": "high",
        "api": [
            "virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
            "setthreadcontext", "getthreadcontext", "queueuserapc", "openprocess",
            "virtualprotect", "virtualprotectex", "ntwritevirtualmemory", "rtlcreateuserthread", "mapviewofsection"
        ],
        "str": [],
    },
    {
        "id": "anti_debug",
        "label": "Anti-Debugging & HWBP Manipulation",
        "severity": "medium",
        "api": [
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "outputdebugstring", "ntsetinformationthread", "dbgbreakpoint", "rtladjustprivilege",
            "ntgetcontextthread", "ntsetcontextthread", "addvectoredexceptionhandler"
        ],
        "str": [
            re.compile(rb"ptrace", re.I), re.compile(rb"IsDebuggerPresent", re.I),
            re.compile(rb"NtGetContextThread", re.I), re.compile(rb"NtSetContextThread", re.I),
            re.compile(rb"AddVectoredExceptionHandler", re.I)
        ],
    },
    {
        "id": "tls_intercept",
        "label": "TLS / SChannel / OpenSSL Stream Interception",
        "severity": "high",
        "api": ["decryptmessage", "encryptmessage", "ssl_read", "ssl_read_ex", "ssl_write", "bcryptverifysignature"],
        "str": [
            re.compile(rb"DecryptMessage", re.I), re.compile(rb"SSL_read", re.I),
            re.compile(rb"BCryptVerifySignature", re.I), re.compile(rb"x-signature-ed25519", re.I)
        ],
    },
    {
        "id": "anti_vm",
        "label": "Anti-VM & Sandbox Detection",
        "severity": "medium",
        "api": [],
        "str": [
            re.compile(rb"vmware", re.I), re.compile(rb"virtualbox", re.I), re.compile(rb"\bvbox\b", re.I),
            re.compile(rb"\bqemu\b", re.I), re.compile(rb"sandbox", re.I), re.compile(rb"\bxen\b", re.I),
            re.compile(rb"sbiedll", re.I)
        ],
    },
    {
        "id": "persistence",
        "label": "Persistence Mechanisms",
        "severity": "high",
        "api": ["regsetvalue", "regcreatekey", "createservice", "startservice", "regopenkey"],
        "str": [re.compile(rb"currentversion\\run", re.I), re.compile(rb"system32\\tasks", re.I), re.compile(rb"schtasks", re.I)],
    },
    {
        "id": "keylog_spy",
        "label": "Keylogging & Screen Capture",
        "severity": "high",
        "api": [
            "getasynckeystate", "setwindowshookex", "getkeystate", "getforegroundwindow",
            "getrawinputdata", "bitblt", "getdc", "getwindowtext"
        ],
        "str": [],
    },
    {
        "id": "dynamic_api",
        "label": "Dynamic API Resolution",
        "severity": "medium",
        "api": ["loadlibrary", "getprocaddress", "getmodulehandle", "ldrloaddll", "ldrgetprocedureaddress"],
        "str": [],
    },
    {
        "id": "privilege",
        "label": "Privilege Escalation & Token Stealing",
        "severity": "medium",
        "api": [
            "adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken",
            "duplicatetokenex", "impersonateloggedonuser", "sedebugprivilege"
        ],
        "str": [re.compile(rb"sedebugprivilege", re.I)],
    },
    {
        "id": "filesystem",
        "label": "File System Manipulation",
        "severity": "info",
        "api": ["createfile", "writefile", "readfile", "deletefile", "movefile", "copyfile", "findfirstfile", "findnextfile", "setfileattributes"],
        "str": [],
    },
    {
        "id": "exec",
        "label": "Process Execution & Shell Spawning",
        "severity": "medium",
        "api": ["createprocess", "winexec", "shellexecute", "ntcreateprocess", "execve", "execvp", "execlp", "popen", "posix_spawn"],
        "str": [re.compile(rb"cmd\.exe", re.I), re.compile(rb"powershell", re.I), re.compile(rb"/bin/sh"), re.compile(rb"/bin/bash")],
    },
]

# Indicator Regex Patterns (on raw strings / byte decoded)
INDICATOR_PATTERNS = {
    "urls": re.compile(r"\bhttps?://[^\s\"'<>]+", re.I),
    "ips": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "domains": re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|dev|co|me)\b", re.I),
    "win_paths": re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|?*]+"),
    "unix_paths": re.compile(r"(?:^|\s)(/(?:usr|home|etc|var|tmp|opt|bin|sbin|root)/[^\s\"'<>]+)"),
    "registry": re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s\"'<>]+", re.I),
    "env_vars": re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%"),
}


def hex_dump(data: bytes, base_offset: int = 0) -> str:
    """Formats bytes into standard hexdump display."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"0x{base_offset + i:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def detect_crypto(data: bytes) -> dict[str, Any]:
    """Scans raw binary data for cryptographic constant signatures."""
    found = []
    for sig in CRYPTO_SIGS:
        pat = sig["bytes"]
        idx = data.find(pat)
        if idx != -1:
            found.append({
                "name": sig["name"],
                "algo": sig["algo"],
                "offset": f"0x{idx:x}",
            })
    algos = list(dict.fromkeys(f["algo"] for f in found))
    return {
        "algorithms": algos,
        "signature_count": len(found),
        "signatures": found,
    }


def extract_indicators(data: bytes, max_per_category: int = 25) -> dict[str, Any]:
    """Extracts structured IoCs (URLs, IPs, emails, domains, paths, registry) from ASCII + UTF-16LE binary strings."""
    text_content = []
    for m in re.findall(rb"[\x20-\x7e]{4,}", data):
        text_content.append(m.decode("ascii", errors="ignore"))
    for w in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data):
        text_content.append(w.decode("utf-16le", errors="ignore"))

    full_blob = "\n".join(text_content)
    indicators: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    total = 0

    for key, pattern in INDICATOR_PATTERNS.items():
        matches = pattern.findall(full_blob)
        # Deduplicate while preserving order
        unique_matches = list(dict.fromkeys(m.strip() if isinstance(m, str) else m[0].strip() for m in matches if m))
        capped = unique_matches[:max_per_category]
        indicators[key] = capped
        counts[key] = len(capped)
        total += len(capped)

    return {
        "total_indicators": total,
        "counts": counts,
        "indicators": indicators,
    }


def match_capabilities(target_path: str, data: bytes | None = None) -> list[dict[str, Any]]:
    """Analyzes imports and strings to classify binary behavior into CAPA-style capabilities."""
    if data is None and target_path and os.path.isfile(target_path):
        try:
            data = safe_read_binary(target_path)
        except Exception:
            return []
    if not data:
        return []

    # Gather import API names if PE
    api_names: list[str] = []
    if pefile and data[:2] == b"MZ":
        pe = None
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            api_names.append(imp.name.decode("latin1", errors="ignore").lower())
        except Exception:
            pass
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception:
                    pass

    out = []
    for rule in CAPABILITY_RULES:
        hits = []
        for pat in rule["api"]:
            for api in api_names:
                if pat in api:
                    hits.append({"kind": "api", "evidence": api})
                    if len(hits) >= 6:
                        break
            if len(hits) >= 6:
                break

        for reg in rule["str"]:
            m = reg.search(data)
            if m:
                matched_snippet = m.group(0).decode("latin1", errors="ignore")
                hits.append({"kind": "string", "evidence": matched_snippet, "offset": f"0x{m.start():x}"})
                if len(hits) >= 8:
                    break

        if hits:
            out.append({
                "id": rule["id"],
                "label": rule["label"],
                "severity": rule["severity"],
                "hit_count": len(hits),
                "hits": hits,
            })

    sev_order = {"high": 0, "medium": 1, "info": 2}
    out.sort(key=lambda x: (sev_order.get(x["severity"], 3), -x["hit_count"]))
    return out


def read_bytes_at(target_path: str, offset: int, length: int = 64) -> dict[str, Any]:
    """Reads raw slice of bytes at offset with bounded size and formatted hexdump."""
    if not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    length = max(1, min(length, 1024))
    try:
        with open(target_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            if offset < 0 or offset >= file_size:
                return {"error": f"Offset dosya sinirlari disinda (Offset: 0x{offset:X}, Boyut: {file_size} bayt)"}
            f.seek(offset)
            chunk = f.read(length)

        return {
            "target": os.path.basename(target_path),
            "offset": f"0x{offset:X}",
            "length": len(chunk),
            "hexdump": hex_dump(chunk, base_offset=offset),
            "hex_raw": chunk.hex(),
        }
    except Exception as e:
        return {"error": f"Bayt okuma hatasi: {str(e)}"}


def read_at_rva(target_path: str, rva: int, length: int = 64) -> dict[str, Any]:
    """Converts a PE RVA (Relative Virtual Address) to file offset and returns hexdump slice."""
    if not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}
    if not pefile:
        return {"error": "pefile kutuphanesi yuklu degil."}

    length = max(1, min(length, 1024))
    try:
        pe = pefile.PE(target_path, fast_load=True)
        file_offset = pe.get_offset_from_rva(rva)
        if file_offset is None:
            return {"error": f"RVA 0x{rva:X} hicbir section ile eslesmedi."}

        with open(target_path, "rb") as f:
            f.seek(file_offset)
            chunk = f.read(length)

        return {
            "target": os.path.basename(target_path),
            "rva": f"0x{rva:X}",
            "file_offset": f"0x{file_offset:X}",
            "length": len(chunk),
            "hexdump": hex_dump(chunk, base_offset=file_offset),
            "hex_raw": chunk.hex(),
        }
    except Exception as e:
        return {"error": f"RVA okuma hatasi: {str(e)}"}


def search_bytes(target_path: str, pattern: str, is_hex: bool = True, max_results: int = 50) -> dict[str, Any]:
    """Searches for a hex or UTF-8/UTF-16LE string pattern in binary safely."""
    if not target_path or not os.path.isfile(target_path):
        return {"error": f"Dosya bulunamadi: {target_path}"}

    try:
        if is_hex:
            clean_hex = pattern.replace(" ", "").replace("0x", "").replace("0X", "")
            search_pat = bytes.fromhex(clean_hex)
        else:
            search_pat = pattern.encode("utf-8")

        if not search_pat:
            return {"error": "Arama deseni bos."}

        data = safe_read_binary(target_path)

        offsets = []
        start = 0
        limit = max(1, min(int(max_results), 200))
        while len(offsets) < limit:
            idx = data.find(search_pat, start)
            if idx == -1:
                break
            offsets.append(f"0x{idx:X}")
            start = idx + 1

        if not offsets and not is_hex:
            u16_pat = pattern.encode("utf-16le")
            start = 0
            while len(offsets) < limit:
                idx = data.find(u16_pat, start)
                if idx == -1:
                    break
                offsets.append(f"0x{idx:X}")
                start = idx + 2

        return {
            "target": os.path.basename(target_path),
            "pattern": f"hex:{clean_hex}" if is_hex else f"utf8:{pattern}",
            "found_count": len(offsets),
            "offsets": offsets,
        }
    except Exception as e:
        return {"error": f"Bayt arama hatasi: {str(e)}"}
