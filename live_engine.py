# -*- coding: utf-8 -*-
"""OmniReverse Live Engine (live_engine.py)
Provides live dynamic instrumentation via Frida and Android device control via ADB
across Windows, macOS, and Linux with option-injection and session-leak guards.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from omni_config import STUDIO_ROOT, get_adb_binary, is_safe_subpath

try:
    import frida
except ImportError:
    frida = None

_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")


def _validate_device_id(device_id: str | None) -> str | None:
    if not device_id:
        return None
    clean = device_id.strip()
    if clean.startswith("-") or not _DEVICE_ID_RE.fullmatch(clean):
        raise ValueError(f"Gecersiz cihaz kimligi formati: {device_id!r}")
    return clean


def frida_list_devices() -> dict[str, Any]:
    """Lists all available Frida devices (local, USB, remote)."""
    if not frida:
        return {"error": "Frida kutuphanesi yuklu degil."}
    try:
        devices = [{"id": dev.id, "name": dev.name, "type": dev.type} for dev in frida.enumerate_devices()]
        return {"count": len(devices), "devices": devices}
    except Exception as e:
        return {"error": f"Frida cihaz listeleme hatasi: {str(e)}"}


def frida_list_processes(device_id: str = "local") -> dict[str, Any]:
    """Enumerates running processes on the given Frida device."""
    if not frida:
        return {"error": "Frida kutuphanesi yuklu degil."}
    try:
        clean_dev = _validate_device_id(device_id) or "local"
        if clean_dev == "local":
            dev = frida.get_local_device()
        elif clean_dev == "usb":
            dev = frida.get_usb_device(timeout=3)
        else:
            dev = frida.get_device(clean_dev)

        procs = [{"pid": p.pid, "name": p.name} for p in dev.enumerate_processes()]
        return {"device": dev.name, "count": len(procs), "processes": procs}
    except Exception as e:
        return {"error": f"Frida surec listeleme hatasi: {str(e)}"}


def frida_inject_script(
    target: str | int,
    script_source: str,
    device_id: str = "local",
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Attaches to a process, injects a Frida JS script safely with guaranteed detach."""
    if not frida:
        return {"error": "Frida kutuphanesi yuklu degil."}
    if not script_source or not script_source.strip():
        return {"error": "Bos Frida betigi gonderilemez."}

    clamped_timeout = max(0.2, min(float(timeout_sec), 30.0))
    captured_messages: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], data: Any) -> None:
        if len(captured_messages) < 500:
            captured_messages.append({"message": message, "data": str(data) if data else None})

    session = None
    script = None
    try:
        clean_dev = _validate_device_id(device_id) or "local"
        if clean_dev == "local":
            dev = frida.get_local_device()
        elif clean_dev == "usb":
            dev = frida.get_usb_device(timeout=3)
        else:
            dev = frida.get_device(clean_dev)

        proc_target = int(target) if isinstance(target, int) or str(target).isdigit() else str(target)
        session = dev.attach(proc_target)
        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        time.sleep(clamped_timeout)

        return {
            "status": "success",
            "target": target,
            "captured_count": len(captured_messages),
            "telemetry": captured_messages,
        }
    except Exception as e:
        return {"error": f"Frida enjeksiyon hatasi: {str(e)}"}
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def adb_list_devices() -> dict[str, Any]:
    """Lists connected Android devices via ADB."""
    adb_bin = get_adb_binary()
    try:
        res = subprocess.run(
            [adb_bin, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return {"raw_output": res.stdout, "status": "ok"}
    except Exception as e:
        return {"error": f"ADB devices hatasi: {str(e)}"}


def adb_shell(command: str, device_id: str | None = None) -> dict[str, Any]:
    """Executes a bounded shell command on an Android device via ADB."""
    if not command or not command.strip():
        return {"error": "Bos ADB komutu."}
    try:
        clean_dev = _validate_device_id(device_id)
        adb_bin = get_adb_binary()
        cmd = [adb_bin]
        if clean_dev:
            cmd.extend(["-s", clean_dev])
        cmd.extend(["shell", command])

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return {
            "exit_code": res.returncode,
            "stdout": (res.stdout or "")[:10000],
            "stderr": (res.stderr or "")[:2000],
        }
    except Exception as e:
        return {"error": f"ADB shell hatasi: {str(e)}"}


def adb_pull_file(remote_path: str, local_path: str, device_id: str | None = None) -> dict[str, Any]:
    """Pulls a file from an Android device into a safe export directory."""
    if not remote_path or remote_path.strip().startswith("-"):
        return {"error": "Gecersiz uzak dosya yolu."}
    try:
        clean_dev = _validate_device_id(device_id)
        pulls_root = (STUDIO_ROOT / ".adb_pulls").resolve()
        pulls_root.mkdir(parents=True, exist_ok=True)

        target_local = Path(local_path).resolve() if local_path else (pulls_root / os.path.basename(remote_path)).resolve()
        if not is_safe_subpath(target_local, STUDIO_ROOT):
            target_local = (pulls_root / Path(local_path).name).resolve()

        adb_bin = get_adb_binary()
        cmd = [adb_bin]
        if clean_dev:
            cmd.extend(["-s", clean_dev])
        cmd.extend(["pull", "--", remote_path, str(target_local)])

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return {
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "local_file": str(target_local) if target_local.exists() else None,
        }
    except Exception as e:
        return {"error": f"ADB pull hatasi: {str(e)}"}


def adb_read_logcat(filter_pattern: str | None = None, lines: int = 50, device_id: str | None = None) -> dict[str, Any]:
    """Reads latest logcat messages from Android device."""
    try:
        clean_dev = _validate_device_id(device_id)
        clamped_lines = max(1, min(int(lines), 2000))
        adb_bin = get_adb_binary()
        cmd = [adb_bin]
        if clean_dev:
            cmd.extend(["-s", clean_dev])
        cmd.extend(["logcat", "-d", "-t", str(clamped_lines)])

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        out = res.stdout or ""
        if filter_pattern:
            out = "\n".join([line for line in out.splitlines() if filter_pattern.lower() in line.lower()])
        return {"logcat": out[:15000]}
    except Exception as e:
        return {"error": f"ADB logcat hatasi: {str(e)}"}
