# -*- coding: utf-8 -*-
"""OmniReverse Session Engine (session_engine.py)
Provides stateful binary sessions, bookmarks, function comments, symbol renaming,
and high-speed in-memory DEX / APK caching with CWE-22 and atomic write protection.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from omni_config import is_safe_subpath, resolve_sessions_dir

_SESSION_LOCK = threading.RLock()
_SESSION_ID_RE = re.compile(r"^sess_[0-9a-f]{16}$")

# In-memory DEX / APK cache (wired into apk_engine / android_ext_engine)
DEX_MEMORY_CACHE: dict[str, dict[str, Any]] = {}


def _get_sessions_dir() -> Path:
    return resolve_sessions_dir()


def _atomic_write_json(target_file: Path, payload: dict[str, Any]) -> None:
    """Writes JSON atomically via temp file + os.replace under lock."""
    parent = target_file.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".sess_tmp_", suffix=".json", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, ensure_ascii=False)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_name, target_file)
    except Exception:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass
        raise


def _stream_sha256(target_path: str) -> str:
    """Computes full streaming SHA-256 hash without loading multi-GB files into RAM."""
    h = hashlib.sha256()
    with open(target_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class BinarySession:
    @staticmethod
    def _session_file(session_id: str) -> Path:
        if not isinstance(session_id, str) or not _SESSION_ID_RE.fullmatch(session_id):
            raise ValueError(f"Gecersiz oturum kimligi formati: {session_id!r}")
        base_dir = _get_sessions_dir()
        sfile = (base_dir / f"{session_id}.json").resolve()
        if not is_safe_subpath(sfile, base_dir):
            raise ValueError("Guvenlik ihlali: Oturum yolu izin verilen dizin disinda.")
        return sfile

    @classmethod
    def open_session(cls, target_path: str) -> dict[str, Any]:
        """Creates or reopens an existing stateful session for a target binary."""
        if not target_path or not os.path.isfile(target_path):
            return {"error": f"Dosya bulunamadi: {target_path}"}

        try:
            full_hash = _stream_sha256(target_path)
        except OSError as exc:
            return {"error": f"Dosya okunamadi: {exc}"}

        session_id = f"sess_{full_hash[:16]}"
        with _SESSION_LOCK:
            sfile = cls._session_file(session_id)
            if sfile.exists():
                try:
                    data = json.loads(sfile.read_text(encoding="utf-8"))
                    if not isinstance(data, dict):
                        return {"error": f"Oturum dosyasi bozuk: {session_id}"}
                    data["last_accessed"] = time.time()
                    _atomic_write_json(sfile, data)
                    return {"status": "reopened", "session_id": session_id, "sha256": full_hash, "data": data}
                except Exception as exc:
                    return {"error": f"Mevcut oturum dosyasi okunamadi (veri korunuyor): {exc}"}

            new_data = {
                "session_id": session_id,
                "target_path": os.path.abspath(target_path),
                "target_name": os.path.basename(target_path),
                "sha256": full_hash,
                "sha256_prefix": full_hash[:16],
                "created_at": time.time(),
                "last_accessed": time.time(),
                "bookmarks": {},
                "comments": {},
                "renamed_symbols": {},
                "notes": [],
            }
            try:
                _atomic_write_json(sfile, new_data)
            except Exception as exc:
                return {"error": f"Oturum olusturulamadi: {exc}"}
            return {"status": "created", "session_id": session_id, "sha256": full_hash, "data": new_data}

    @classmethod
    def annotate(cls, session_id: str, kind: str, address_or_symbol: str, value: str) -> dict[str, Any]:
        """Adds or updates a bookmark, comment, symbol rename, or note."""
        try:
            sfile = cls._session_file(session_id)
        except ValueError as exc:
            return {"error": str(exc)}

        with _SESSION_LOCK:
            if not sfile.exists():
                return {"error": f"Oturum bulunamadi: {session_id}. Once 'open' ile oturum acin."}
            try:
                data = json.loads(sfile.read_text(encoding="utf-8"))
                if kind == "bookmark":
                    data.setdefault("bookmarks", {})[str(address_or_symbol)] = str(value)
                elif kind == "comment":
                    data.setdefault("comments", {})[str(address_or_symbol)] = str(value)
                elif kind == "rename":
                    data.setdefault("renamed_symbols", {})[str(address_or_symbol)] = str(value)
                elif kind == "note":
                    data.setdefault("notes", []).append({"time": time.time(), "text": str(value)})
                else:
                    return {"error": f"Gecersiz isaret turu '{kind}'. Secenekler: bookmark, comment, rename, note"}

                data["last_accessed"] = time.time()
                _atomic_write_json(sfile, data)
                return {
                    "status": "updated",
                    "session_id": session_id,
                    "kind": kind,
                    "key": address_or_symbol,
                    "value": value,
                }
            except Exception as exc:
                return {"error": f"Oturum guncelleme hatasi: {exc}"}

    @classmethod
    def get_session(cls, session_id: str) -> dict[str, Any]:
        try:
            sfile = cls._session_file(session_id)
        except ValueError as exc:
            return {"error": str(exc)}

        with _SESSION_LOCK:
            if not sfile.exists():
                return {"error": f"Oturum bulunamadi: {session_id}"}
            try:
                data = json.loads(sfile.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {"error": "Gecersiz oturum verisi."}
            except Exception as exc:
                return {"error": f"Oturum okuma hatasi: {exc}"}

    @classmethod
    def list_sessions(cls) -> list[dict[str, Any]]:
        results = []
        base_dir = _get_sessions_dir()
        if not base_dir.is_dir():
            return results
        with _SESSION_LOCK:
            for sf in sorted(base_dir.glob("sess_*.json")):
                try:
                    d = json.loads(sf.read_text(encoding="utf-8"))
                    if not isinstance(d, dict):
                        continue
                    results.append({
                        "session_id": d.get("session_id"),
                        "target_name": d.get("target_name"),
                        "sha256_prefix": d.get("sha256_prefix", ""),
                        "bookmarks_count": len(d.get("bookmarks") or {}),
                        "comments_count": len(d.get("comments") or {}),
                        "renamed_symbols_count": len(d.get("renamed_symbols") or {}),
                    })
                except Exception:
                    continue
        return results


def get_cached_dex(apk_path: str) -> dict[str, Any] | None:
    """Returns cached DEX structures for fast single-class queries."""
    with _SESSION_LOCK:
        return DEX_MEMORY_CACHE.get(os.path.abspath(apk_path))


def set_cached_dex(apk_path: str, dex_data: dict[str, Any]) -> None:
    """Stores parsed DEX structures into memory."""
    with _SESSION_LOCK:
        key = os.path.abspath(apk_path)
        if len(DEX_MEMORY_CACHE) >= 10 and key not in DEX_MEMORY_CACHE:
            DEX_MEMORY_CACHE.pop(next(iter(DEX_MEMORY_CACHE)))
        DEX_MEMORY_CACHE[key] = dex_data
