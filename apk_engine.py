# -*- coding: utf-8 -*-
"""OmniReverse APK Engine (apk_engine.py)
Combines Android APK structure triage, safe ZipBomb-guarded DEX string extraction,
Apktool manifest/resource decoding (with XXE entity rejection), secret masking,
and JSON-serializable structured output.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from omni_config import get_apktool_cmd, mask_secret_preview, safe_zip_read
from session_engine import get_cached_dex, set_cached_dex

PROTECTOR_SIGNATURES = {
    "Bangcle / SecShell": ["libSecShell.so", "libsecmain.so", "assets/tosversion"],
    "Tencent / Legu": ["libtup.so", "libshell.so", "0111111111.dex"],
    "Qihoo 360": ["libprotectClass.so", "libjiagu.so", "libjiagu_art.so"],
    "Ijiami": ["libmobisec.so", "ijm_lib/"],
    "Baidu Protect": ["libbaiduprotect.so"],
    "Alibaba / Ali": ["libsgmain.so", "libsecuritysdk.so"],
    "SecNeo / Nagra": ["libDexHelper.so", "libsecexe.so"],
    "DexGuard": ["dexguard-annotation", "dexguard/"],
}

FRAMEWORK_SIGNATURES = {
    "Flutter": ["libflutter.so", "libapp.so", "assets/flutter_assets"],
    "React Native": ["libreactnativejni.so", "assets/index.android.bundle"],
    "Capacitor / Ionic": ["assets/capacitor.config.json", "assets/public/app.js"],
    "Cordova / PhoneGap": ["assets/www/cordova.js", "assets/www/index.html"],
    "Unity 3D": ["libunity.so", "assets/bin/Data"],
    "Xamarin / .NET MAUI": ["libmonodroid.so", "assemblies/"],
}

URL_REGEX = re.compile(rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\"\'\x00<>]+)?")
OPENAI_KEY_REGEX = re.compile(rb"sk-[a-zA-Z0-9_\-]{25,}")
GROQ_KEY_REGEX = re.compile(rb"gsk_[a-zA-Z0-9_\-]{20,}")
CLAUDE_KEY_REGEX = re.compile(rb"sk-ant-[a-zA-Z0-9_\-]{25,}")
GEMINI_KEY_REGEX = re.compile(rb"AIza[0-9A-Za-z\-_]{35}")


def _safe_parse_xml(xml_path: Path) -> ET.Element:
    """Rejects XML external/internal entity declarations (CWE-611 / Billion Laughs)."""
    raw_txt = xml_path.read_text(encoding="utf-8", errors="replace")
    if "<!DOCTYPE" in raw_txt.upper() or "<!ENTITY" in raw_txt.upper():
        raise ValueError("Guvensiz XML ENTITY/DOCTYPE bildirimi reddedildi.")
    return ET.fromstring(raw_txt)


def analyze_apk(apk_path: Path | str, log: list[str] | None = None) -> dict[str, Any]:
    """Performs deep Android APK reverse engineering with safe memory and XML bounds."""
    if log is None:
        log = []
    apk_p = Path(apk_path)
    if not apk_p.is_file():
        return {"error": f"APK dosyasi bulunamadi: {apk_path}"}

    cached = get_cached_dex(str(apk_p))
    if cached is not None:
        log.append(f"[APK-Engine] Önbellekten yüklendi: {apk_p.name}")
        return cached

    log.append(f"[APK-Engine] Analiz başlatıldı: {apk_p.name}")
    endpoints_set: set[str] = set()
    secrets_set: set[str] = set()

    result: dict[str, Any] = {
        "package_name": "Bilinmiyor",
        "version": "Bilinmiyor",
        "framework": "Native Android (Java/Kotlin)",
        "protectors": [],
        "dex_files": [],
        "native_libs": [],
        "endpoints": [],
        "secrets": [],
        "secrets_masked": [],
        "permissions": [],
        "activities": [],
        "extracted_preview": "",
    }

    if not zipfile.is_zipfile(apk_p):
        result["error"] = "Gecerli bir ZIP/APK arsivi degil."
        return result

    try:
        with zipfile.ZipFile(apk_p, "r") as z:
            names = z.namelist()
            result["dex_files"] = [n for n in names if n.endswith(".dex")]
            result["native_libs"] = [n for n in names if n.endswith(".so")]

            for fw, sigs in FRAMEWORK_SIGNATURES.items():
                if any(any(s in n for n in names) for s in sigs):
                    result["framework"] = fw
                    break
            log.append(f"[APK-Engine] Çerçeve (Framework): {result['framework']}")

            for prot, sigs in PROTECTOR_SIGNATURES.items():
                if any(any(s in n for n in names) for s in sigs):
                    result["protectors"].append(prot)
            if result["protectors"]:
                log.append(f"[APK-Engine] Tespit edilen koruyucu: {', '.join(result['protectors'])}")
            else:
                log.append("[APK-Engine] Ticari koruyucu (Packer/Shield) tespit edilmedi.")

            for dex in result["dex_files"][:12]:
                dex_bytes = safe_zip_read(z, dex)
                for u in URL_REGEX.findall(dex_bytes):
                    us = u.decode("utf-8", errors="ignore")
                    if any(k in us.lower() for k in ("api", "groq", "chat", "completions", "ai", "openai", "anthropic", "v1", "model", "token")):
                        endpoints_set.add(us)
                for rx in (GROQ_KEY_REGEX, OPENAI_KEY_REGEX, CLAUDE_KEY_REGEX, GEMINI_KEY_REGEX):
                    for k in rx.findall(dex_bytes):
                        secrets_set.add(k.decode("latin1", errors="ignore"))

            js_assets = [n for n in names if n.startswith("assets/") and n.endswith((".js", ".json", ".html"))]
            if js_assets:
                log.append(f"[APK-Engine] {len(js_assets)} web varlığı bulundu (Capacitor/Cordova/RN).")
                for jf in js_assets[:15]:
                    content = safe_zip_read(z, jf, max_bytes=32 * 1024 * 1024)
                    for u in URL_REGEX.findall(content):
                        us = u.decode("utf-8", errors="ignore")
                        if any(k in us.lower() for k in ("api", "groq", "chat", "completions", "ai", "openai", "anthropic", "v1")):
                            endpoints_set.add(us)
                    for rx in (GROQ_KEY_REGEX, OPENAI_KEY_REGEX):
                        for k in rx.findall(content):
                            secrets_set.add(k.decode("latin1", errors="ignore"))
    except Exception as exc:
        log.append(f"[APK-Engine-Err] Zip okuma hatası: {exc}")

    apktool_cmd = get_apktool_cmd()
    if apktool_cmd is not None:
        temp_dir = Path(tempfile.mkdtemp(prefix="omni_apktool_"))
        try:
            cmd = [*apktool_cmd, "d", "-s", "-f", "-o", str(temp_dir), str(apk_p)]
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if p.returncode == 0:
                log.append("[APK-Apktool] AndroidManifest.xml ve kaynak tabloları başarıyla çözüldü.")
                manifest_path = temp_dir / "AndroidManifest.xml"
                if manifest_path.is_file():
                    try:
                        root = _safe_parse_xml(manifest_path)
                        result["package_name"] = root.attrib.get("package", "Bilinmiyor")
                        v_name = next((v for k, v in root.attrib.items() if k.endswith("versionName")), None)
                        result["version"] = v_name or "1.0"
                        for elem in root.findall("uses-permission"):
                            for k, v in elem.attrib.items():
                                if k.endswith("name"):
                                    result["permissions"].append(v.split(".")[-1])
                        for act in root.iter("activity"):
                            for k, v in act.attrib.items():
                                if k.endswith("name"):
                                    result["activities"].append(v.split(".")[-1])
                    except Exception as e_xml:
                        log.append(f"[APK-Manifest-Err] XML ayrıştırma uyarısı: {e_xml}")

                strings_path = temp_dir / "res" / "values" / "strings.xml"
                if strings_path.is_file():
                    try:
                        stxt = strings_path.read_text(encoding="utf-8", errors="ignore")
                        for m in re.finditer(r'<string name="([^"]+)">([^<]+)</string>', stxt):
                            sname, sval = m.groups()
                            if any(k in sname.lower() for k in ("api_key", "groq", "openai", "token", "auth", "secret")):
                                secrets_set.add(f"{sname}={sval}")
                    except Exception:
                        pass
            else:
                log.append(f"[APK-Apktool-Err] Çıkış Kodu {p.returncode}: {p.stderr[:200]}")
        except Exception as exc:
            log.append(f"[APK-Apktool-Err] Çalıştırma hatası: {exc}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    result["endpoints"] = sorted(endpoints_set)
    result["secrets"] = sorted(secrets_set)
    result["secrets_masked"] = [mask_secret_preview(s) for s in result["secrets"]]

    preview_lines = [
        "// OmniReverse APK Analysis Summary",
        f"Package: {result['package_name']} (v{result['version']})",
        f"Framework: {result['framework']}",
        f"Protectors: {', '.join(result['protectors']) if result['protectors'] else 'None'}",
        f"DEX Files: {len(result['dex_files'])} | Native .so: {len(result['native_libs'])}",
        "",
        "// Discovered AI Endpoints:",
    ]
    if result["endpoints"]:
        for ep in result["endpoints"][:15]:
            preview_lines.append(f"  - {ep}")
    else:
        preview_lines.append("  (No direct endpoints found in bytecode)")

    preview_lines.extend(["", "// Discovered Secrets & API Keys (Masked):"])
    if result["secrets_masked"]:
        for sec in result["secrets_masked"]:
            preview_lines.append(f"  - {sec}")
    else:
        preview_lines.append("  (No cleartext API keys hardcoded)")

    preview_lines.extend([
        "",
        f"// Permissions ({len(result['permissions'])}): {', '.join(result['permissions'][:8])}",
        f"// Main Activities ({len(result['activities'])}): {', '.join(result['activities'][:5])}",
    ])

    result["extracted_preview"] = "\n".join(preview_lines)
    set_cached_dex(str(apk_p), result)
    return result
