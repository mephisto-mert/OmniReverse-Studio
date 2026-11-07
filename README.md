# OmniReverse Studio v3.2

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![C++20](https://img.shields.io/badge/C%2B%2B-20%20MSVC%20%7C%20GCC-green.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC%20v1.0-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

OmniReverse Studio is a 42-engine reverse engineering, binary unpacking, symbolic execution, and static analysis suite. It exposes a unified interface across a native x64 Windows GUI (`OmniReverse_Studio.exe`), a headless CLI with single-file HTML audit export, and a Model Context Protocol (MCP) server for automated agent integration.

---

## Architecture & Subsystems

```
                                  [ Target Artifact ]
           (PE / ELF / Mach-O / APK / IPA / ASAR / HBC / AOT / PyInstaller / WASM)
                                          │
                                 ┌────────┴────────┐
                                 ▼                 ▼
                         Static Triage      Dynamic & Emulation
                      (Capstone / LIEF)     (Unicorn / Frida / HWBP)
                                 │                 │
            ┌────────────────────┼─────────────────┴──────────────────┐
            ▼                    ▼                                    ▼
    [ Symbolics & MBA ]  [ Runtimes & Unpackers ]             [ Memory & Patch ]
    - Z3 BitVec Solver   - Costura / PyInstaller              - BasicBlock CFG (SVG)
    - OLLVM Unflatten    - Flutter AOT / Hermes HBC           - NOP / JMP / RET Patch
    - Mixed-Boolean-Arith - Unity IL2CPP / Bun SEA            - Live RAM Pointer Scan
            │                    │                                    │
            └────────────────────┬────────────────────────────────────┘
                                 ▼
                     Unified Integration Layer
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
   CLI Pipeline           Native Win32 GUI            MCP Server
 (omni_cli_runner.py)   (OmniReverse_Studio.exe) (JSON-RPC via stdio)
```

### Engine Breakdown (42 Modules)

| Category | Modules | Core Technical Mechanics |
| :--- | :--- | :--- |
| **Native Disassembly & Headers** | `granular_engine`, `native_packer_engine` | PE32/PE32+, ELF, Mach-O Fat/Thin parsing via LIEF/Capstone. RIP-relative LEA reconstruction, IAT rebuild via Scylla heuristics, SysWhispers/Hell's Gate SSN extraction. |
| **Dynamic Tracer & Hardware BPs** | `native_tls_hwbp_engine`, `dynamic_unpacker` | DR0–DR3 hardware breakpoint harness. VEH + `NtGetContextThread` context hiding, SChannel `DecryptMessage` and OpenSSL `SSL_read` inline hooking without integrity trip. |
| **Mobile & Cross-Platform** | `mobile_deep_engine`, `apk_engine`, `android_ext_engine` | Android APK/AXML/ARSC parser, DEX multi-dex string pool extractor. React Native Hermes (`.hbc`) bytecode deserializer, Flutter Dart AOT Snapshot (`libapp.so`) reader, Unity IL2CPP `global-metadata.dat` string/method recovery. |
| **Desktop Application Unpackers** | `modern_packers_engine` | Electron `.asar` virtual filesystem reader, V8 `.jsc` cache extractor, PyInstaller archive unpacker (`pyz` extraction), Bun single-executable application (SEA) bundle splitter. |
| **Symbolic Execution & Deobfuscation**| `symbolic_protocol_engine`, `mba_engine` | Z3 SMT solver for AST-driven serial/keygen constraint verification (`BitVec(64)`). Mixed Boolean-Arithmetic (MBA) simplifier using Hensel modular inversion. OLLVM control-flow unflattening state-machine solver. |
| **Patching & Memory Forensics** | `visual_patch_memory_engine` | Recursive traversal disassembler for basic-block control flow graph (CFG) generation (JSON + standalone SVG). Non-destructive byte patcher (`NOP`, `force_jmp`, `ret_true`). Windows VirtualQueryEx process RAM scanner with multi-level pointer path resolving. |
| **Static Code & Protocol Auditing** | `sqli_detector`, `web_bundle_engine`, `wasm_engine`, `report_generator` | Python AST and regex taint tracking for SQL injection detection. Webpack SourceMap reconstructor (`.map` recovery). WebAssembly (`.wasm`) section decoder. Single-file dark-theme HTML report generator. |

---

## Quickstart

### 1. Requirements

* Python 3.10 – 3.12
* Windows 10/11 x64, Linux (Ubuntu 22.04+), or macOS (Apple Silicon / Intel)
* Optional: C++ compiler (MSVC v143 or GCC 12+) for building the native injector DLLs.

```bash
cd OmniReverse-Studio
pip install -e .
```

### 2. Standalone Native GUI Launcher

Launch the high-performance Windows x64 GUI with zero web dependencies:

```bash
# Launch Native GUI directly
OmniReverse_Studio.exe
```

### 3. Command-Line Interface (CLI)

Run automated triage, unpacking, or export standalone HTML security audit reports:

```bash
# Export standalone HTML security audit report
omni target_sample.exe --export-html security_audit.html

# Deep triage & vulnerability scan
omni target_sample.exe --mode deep

# Unpack modern application packages (Electron ASAR, PyInstaller, Flutter AOT)
omni app.asar --mode unpack

# Run full v3.2 inspection suite with CFG graph generation
omni target_lib.so --mode v3_suite
```

### 4. 1-Click AI Agent MCP Setup

OmniReverse Studio natively implements the Model Context Protocol (MCP) over `stdio`. Register the server into your installed AI agent in one command:

```bash
# Register in Claude Desktop, Cursor, and Antigravity simultaneously
python omni_server.py --install-all

# Or target a specific client
python omni_server.py --install-claude
python omni_server.py --install-cursor
python omni_server.py --install-antigravity
```

Manual configuration snippet (`claude_desktop_config.json` or `mcp.json`):

```json
{
  "mcpServers": {
    "omni-reverse": {
      "command": "python",
      "args": [
        "C:/path/to/OmniReverse-Studio/omni_server.py"
      ]
    }
  }
}
```

Available MCP Tools:
- `omni_auto_orchestrate`: Magic-byte classification and automatic multi-engine triage.
- `omni_advanced_native`: PE/ELF/Mach-O header, Scylla IAT, direct syscall extraction.
- `omni_mobile_deep`: Flutter AOT, React Native Hermes, Unity IL2CPP, IPA Mach-O.
- `omni_modern_unpacker`: Electron ASAR, PyInstaller PYZ, Bun SEA bundles.
- `omni_symbolic_protocol`: Z3 SMT constraint solving, OLLVM unflattening, Protobuf recovery.
- `omni_patch_cfg_memory`: Basic-block SVG CFG generation, non-destructive binary patch, live RAM pointer scan.
- `omni_bsim_vault`: SQLite FTS5 function signature search and binary diffing.

### 5. Automated CI/CD Audits (GitHub Action)

Add OmniReverse binary audit into your GitHub Actions workflow:

```yaml
- name: OmniReverse Security Audit
  uses: OmniReverse-Studio/OmniReverse-Studio@main
  with:
    target: 'dist/target_binary.exe'
    mode: 'all'
    output-report: 'dist/security_audit.html'
```

---

## Educational Examples & Challenges

The `examples/` directory contains educational scripts demonstrating practical reverse engineering and constraint solving:

* **`examples/crackme_xor.py`**: A 15-character rolling XOR keygen challenge.
  ```bash
  python examples/crackme_xor.py OMNI-REVERSE-32
  ```
* **`examples/sample_z3_solver.py`**: Simplifies Mixed Boolean-Arithmetic (MBA) expressions and computes 64-bit Hensel modular inverses.
  ```bash
  python examples/sample_z3_solver.py
  ```
* **`examples/sample_hermes_unpack.py`**: Demonstrates React Native Hermes (`.hbc`) bytecode header parsing and endpoint recovery.
  ```bash
  python examples/sample_hermes_unpack.py
  ```

---

## Verification & Test Suite

The test harness exercises all 42 engines against synthetic and real binary targets (packed executables, mobile bundles, and memory buffers):

```bash
# Run full test suite
python -m pytest tests/ -v
```

---

## Security & Disclosure

This project is built strictly for authorized defensive reverse engineering, malware analysis, interoperability research, and vulnerability discovery. Binary patching is non-destructive and operates on output copies (`*_patched`) by default. Dynamic memory manipulation features require explicit operator flags.

## License

MIT License. See [LICENSE](LICENSE) for details.
