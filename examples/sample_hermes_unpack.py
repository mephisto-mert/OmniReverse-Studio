# -*- coding: utf-8 -*-
"""
OmniReverse React Native Hermes Bytecode (.hbc) Inspection Example
Demonstrates how OmniReverse parses Hermes bytecode files, validates
header magic, extracts function counts, and reconstructs endpoints.
"""
import sys
import struct
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mobile_deep_engine import decompile_hermes_bytecode, HERMES_MAGIC

def generate_mock_hermes_bytecode() -> bytes:
    """Constructs a valid Hermes Bytecode (.hbc) header with embedded strings for demonstration."""
    # Hermes Header format:
    # 8 bytes: Magic (0x1f1903c103bc1fc6)
    # 4 bytes: Version (e.g. 96 for RN 0.73+)
    # 20 bytes: SHA1 hash
    # 4 bytes: File length
    # 4 bytes: Global Code Index
    # 4 bytes: Function Count
    # 4 bytes: String Count
    # 4 bytes: Identifier Count
    version = 96
    sha1 = b"\xaa" * 20
    file_len = 1024
    global_idx = 0
    func_count = 42
    string_count = 15
    ident_count = 8

    header = HERMES_MAGIC + struct.pack(
        "<I20sIIIII",
        version,
        sha1,
        file_len,
        global_idx,
        func_count,
        string_count,
        ident_count,
    )

    payload = (
        b"\x00" * 32
        + b"https://api.internal.service/v1/auth\x00"
        + b"https://telemetry.analytics.io/collect\x00"
        + b"authenticateUser\x00"
        + b"onLoginSuccess\x00"
        + b"decryptPayload\x00"
        + b"\x00" * (file_len - len(header) - 150)
    )
    return header + payload

def main():
    print("=================================================================")
    print("  OmniReverse Studio — React Native Hermes (.hbc) Showcase")
    print("=================================================================\n")

    # Generate synthetic Hermes bytecode file
    hbc_data = generate_mock_hermes_bytecode()
    with tempfile.NamedTemporaryFile(suffix=".hbc", delete=False) as tmp:
        tmp.write(hbc_data)
        tmp_path = tmp.name

    try:
        print(f"[*] Analyzing Hermes Bytecode Artifact: {tmp_path}")
        result = decompile_hermes_bytecode(tmp_path)

        print(f"[+] Hermes Detected: {result.get('is_hermes')}")
        print(f"[+] Bytecode Version: v{result.get('hbc_version')}")
        print(f"[+] Recovered Function Count: {result.get('function_count')}")
        print(f"[+] String Table Count: {result.get('string_count')}")
        print(f"[+] Extracted Endpoints: {result.get('endpoints_recovered')}")
        print("\n[*] Reconstructed Pseudo-JavaScript Preview:")
        print(result.get("pseudo_javascript", ""))
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    print("\n[+] Hermes bytecode inspection demonstration complete.")

if __name__ == "__main__":
    main()
