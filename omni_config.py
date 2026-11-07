# -*- coding: utf-8 -*-
"""OmniReverse Cross-Platform Configuration & Security Boundaries (omni_config.py)
Centralizes portable tool discovery (Windows, macOS, Linux), safe file/archive reading,
path-traversal confinement, and secret masking.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

STUDIO_ROOT = Path(__file__).resolve().parent
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

MAX_TARGET_BYTES = int(os.environ.get("OMNI_MAX_TARGET_BYTES", str(256 * 1024 * 1024)))
MAX_ZIP_MEMBER_BYTES = int(os.environ.get("OMNI_MAX_ZIP_MEMBER_BYTES", str(128 * 1024 * 1024)))
MAX_ZLIB_DECOMPRESS_BYTES = 16 * 1024 * 1024


def resolve_sessions_dir() -> Path:
    """Resolves a writable cross-platform session storage directory."""
    env_dir = os.environ.get("OMNI_SESSIONS_DIR", "").strip()
    candidates = []
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(STUDIO_ROOT / ".sessions")
    candidates.append(Path.home() / ".omnireverse" / "sessions")

    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            return cand.resolve()
        except OSError:
            continue
    return (STUDIO_ROOT / ".sessions")


def is_safe_subpath(candidate: Path, base_dir: Path) -> bool:
    """Verifies candidate resolves strictly inside base_dir (CWE-22 protection)."""
    try:
        resolved_base = base_dir.resolve()
        resolved_cand = candidate.resolve()
        return resolved_cand == resolved_base or resolved_cand.is_relative_to(resolved_base)
    except (OSError, ValueError):
        return False


def safe_read_binary(target_path: str | Path, max_bytes: int = MAX_TARGET_BYTES) -> bytes:
    """Reads a binary file safely with an upper memory bound (CWE-770 protection)."""
    p = Path(target_path)
    if not p.is_file():
        raise FileNotFoundError(f"Dosya bulunamadi: {target_path}")
    fsize = p.stat().st_size
    if fsize > max_bytes:
        raise ValueError(
            f"Dosya boyutu guvenli bellek sinirini asiyor ({fsize} > {max_bytes} bayt)."
        )
    return p.read_bytes()


def safe_zip_read(zf: zipfile.ZipFile, member_name: str, max_bytes: int = MAX_ZIP_MEMBER_BYTES) -> bytes:
    """Reads a ZIP/APK entry after verifying uncompressed size against ZipBomb limits (CWE-409)."""
    info = zf.getinfo(member_name)
    if info.file_size > max_bytes:
        raise ValueError(
            f"Arsiv ogesi '{member_name}' guvenli acilma sinirini asiyor ({info.file_size} > {max_bytes} bayt)."
        )
    with zf.open(info, "r") as fp:
        data = fp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"Arsiv ogesi '{member_name}' beklenenden buyuk veri uretti.")
    return data


def mask_secret_preview(raw_secret: str) -> str:
    """Masks middle characters of harvested API keys for safe report display (CWE-312)."""
    if "=" in raw_secret:
        k, v = raw_secret.split("=", 1)
        return f"{k}={mask_secret_preview(v)}"
    s = raw_secret.strip()
    if len(s) <= 10:
        return s[:2] + "****"
    return f"{s[:6]}...{s[-4:]}"


def get_ghidra_analyzer() -> Path | None:
    """Resolves Ghidra headless analyzer script across Windows, macOS, and Linux."""
    script_name = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
    for env_key in ("OMNI_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        val = os.environ.get(env_key, "").strip()
        if val:
            cand = Path(val) / "support" / script_name
            if cand.is_file():
                return cand

    which_hit = shutil.which(script_name) or shutil.which("analyzeHeadless")
    if which_hit:
        return Path(which_hit)

    search_roots = [Path(r"C:\Tools")] if IS_WINDOWS else [Path("/opt"), Path("/usr/local"), Path.home()]
    for root in search_roots:
        if root.is_dir():
            for match in sorted(root.glob("ghidra*"), reverse=True):
                cand = match / "support" / script_name
                if cand.is_file():
                    return cand
    return None


def get_wabt_tool(tool_base: str) -> Path | None:
    """Resolves WABT binary (wasm2wat, wasm-objdump, wasm2c) portably."""
    exe_name = f"{tool_base}.exe" if IS_WINDOWS else tool_base
    env_dir = os.environ.get("OMNI_WABT_DIR", "").strip()
    if env_dir:
        cand = Path(env_dir) / exe_name
        if cand.is_file():
            return cand

    which_hit = shutil.which(exe_name) or shutil.which(tool_base)
    if which_hit:
        return Path(which_hit)

    if IS_WINDOWS and Path(r"C:\Tools").is_dir():
        for match in sorted(Path(r"C:\Tools").glob("wabt*"), reverse=True):
            cand = match / "bin" / exe_name
            if cand.is_file():
                return cand
    return None


def get_apktool_cmd() -> list[str] | None:
    """Resolves apktool CLI or apktool.jar invocation portably."""
    env_jar = os.environ.get("OMNI_APKTOOL_JAR", "").strip()
    if env_jar and Path(env_jar).is_file():
        return ["java", "-jar", env_jar]

    which_apktool = shutil.which("apktool.bat" if IS_WINDOWS else "apktool") or shutil.which("apktool")
    if which_apktool:
        return [which_apktool]

    win_jar = Path(r"C:\Tools\apktool.jar")
    if IS_WINDOWS and win_jar.is_file() and shutil.which("java"):
        return ["java", "-jar", str(win_jar)]
    return None


def get_jadx_cmd() -> list[str] | None:
    """Resolves jadx CLI binary portably (avoids MCP server JAR confusion)."""
    env_bin = os.environ.get("OMNI_JADX_BIN", "").strip()
    if env_bin and Path(env_bin).is_file():
        return [env_bin]

    which_jadx = shutil.which("jadx.bat" if IS_WINDOWS else "jadx") or shutil.which("jadx")
    if which_jadx:
        return [which_jadx]

    if IS_WINDOWS and Path(r"C:\Tools").is_dir():
        for match in sorted(Path(r"C:\Tools").glob("jadx*"), reverse=True):
            if match.is_dir():
                cand = match / "bin" / "jadx.bat"
                if cand.is_file():
                    return [str(cand)]
    return None


def get_adb_binary() -> str:
    """Resolves Android ADB executable across Windows, macOS, and Linux."""
    env_adb = os.environ.get("OMNI_ADB_BIN", "").strip()
    if env_adb and Path(env_adb).is_file():
        return env_adb

    which_adb = shutil.which("adb.exe" if IS_WINDOWS else "adb") or shutil.which("adb")
    if which_adb:
        return which_adb

    exe = "adb.exe" if IS_WINDOWS else "adb"
    sdk_envs = [os.environ.get("ANDROID_HOME", ""), os.environ.get("ANDROID_SDK_ROOT", "")]
    default_sdks = [
        Path.home() / "AppData" / "Local" / "Android" / "Sdk",
        Path.home() / "Library" / "Android" / "sdk",
        Path.home() / "Android" / "Sdk",
    ]
    for root in [Path(p) for p in sdk_envs if p] + default_sdks:
        cand = root / "platform-tools" / exe
        if cand.is_file():
            return str(cand)
    return "adb"


def sanitize_relative_filename(name: str) -> str:
    """Sanitizes untrusted relative paths/filenames against CWE-22 traversal and invalid characters."""
    if not name:
        return "unnamed"
    cleaned = name.replace("\\", "/").lstrip("/")
    parts = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", p) for p in cleaned.split("/") if p and p not in (".", "..")]
    return "/".join(parts) if parts else "unnamed"


# Unified aliases used by pipeline, MCP server, and Web Studio
def find_ghidra_headless() -> str | None:
    p = get_ghidra_analyzer()
    return str(p) if p else None


def find_jadx_executable() -> str | None:
    cmd = get_jadx_cmd()
    return cmd[0] if cmd else None


def find_wabt_tool(tool_base: str) -> str | None:
    p = get_wabt_tool(tool_base)
    return str(p) if p else None


def find_apktool_jar() -> str | None:
    cmd = get_apktool_cmd()
    return cmd[-1] if cmd else None


def find_adb_executable() -> str | None:
    b = get_adb_binary()
    return b if (Path(b).is_file() or shutil.which(b)) else None
