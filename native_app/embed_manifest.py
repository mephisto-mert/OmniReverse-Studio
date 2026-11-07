# -*- coding: utf-8 -*-
"""Embeds 4-byte-aligned Win32 Common Controls v6 + PerMonitorV2 High-DPI RT_MANIFEST into PE and verifies Activation Context."""
from __future__ import annotations

import ctypes
import sys

RT_MANIFEST = 24
CREATEPROCESS_MANIFEST_RESOURCE_ID = 1

_RAW_MANIFEST_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity
      version="2.1.0.0"
      processorArchitecture="amd64"
      name="OmniReverse.Studio.Native"
      type="win32"
  />
  <description>OmniReverse Studio x64 Native Reverse Engineering Suite</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
          type="win32"
          name="Microsoft.Windows.Common-Controls"
          version="6.0.0.0"
          processorArchitecture="*"
          publicKeyToken="6595b64144ccf1df"
          language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>"""

# Pad with ASCII spaces (never NUL bytes) to an exact 4-byte DWORD boundary for Windows SxS loader compatibility
_pad_len = (4 - (len(_RAW_MANIFEST_XML) % 4)) % 4
MANIFEST_XML = _RAW_MANIFEST_XML + (b" " * _pad_len)


class _ACTCTXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("lpSource", ctypes.c_wchar_p),
        ("wProcessorArchitecture", ctypes.c_ushort),
        ("wLangId", ctypes.c_ushort),
        ("lpAssemblyDirectory", ctypes.c_wchar_p),
        ("lpResourceName", ctypes.c_void_p),
        ("lpApplicationName", ctypes.c_wchar_p),
        ("hModule", ctypes.c_void_p),
    ]


def verify_activation_context(pe_path: str) -> bool:
    if sys.platform != "win32":
        return False
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateActCtxW.argtypes = [ctypes.POINTER(_ACTCTXW)]
    k32.CreateActCtxW.restype = ctypes.c_void_p
    k32.ReleaseActCtx.argtypes = [ctypes.c_void_p]
    k32.ReleaseActCtx.restype = None

    ctx = _ACTCTXW()
    ctx.cbSize = ctypes.sizeof(_ACTCTXW)
    ctx.dwFlags = 0x008  # ACTCTX_FLAG_RESOURCE_NAME_VALID
    ctx.lpSource = pe_path
    ctx.lpResourceName = ctypes.c_void_p(CREATEPROCESS_MANIFEST_RESOURCE_ID)
    ctypes.set_last_error(0)
    handle = k32.CreateActCtxW(ctypes.byref(ctx))
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        return False
    k32.ReleaseActCtx(handle)
    return True


def embed_manifest(pe_path: str) -> bool:
    if sys.platform != "win32":
        return False

    k32 = ctypes.windll.kernel32
    k32.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
    k32.BeginUpdateResourceW.restype = ctypes.c_void_p
    k32.UpdateResourceW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    k32.UpdateResourceW.restype = ctypes.c_int
    k32.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_int]
    k32.EndUpdateResourceW.restype = ctypes.c_int

    h_upd = k32.BeginUpdateResourceW(pe_path, 0)
    if not h_upd:
        return False
    ok = k32.UpdateResourceW(
        h_upd,
        ctypes.c_void_p(RT_MANIFEST),
        ctypes.c_void_p(CREATEPROCESS_MANIFEST_RESOURCE_ID),
        1033,
        MANIFEST_XML,
        len(MANIFEST_XML),
    )
    if not ok:
        k32.EndUpdateResourceW(h_upd, 1)
        return False
    if not k32.EndUpdateResourceW(h_upd, 0):
        return False
    return verify_activation_context(pe_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python embed_manifest.py <pe_path>")
        sys.exit(1)
    target = sys.argv[1]
    if embed_manifest(target):
        print(
            f"[+] Embedded & verified 4-byte-aligned RT_MANIFEST ({len(MANIFEST_XML)} bytes, Common-Controls v6.0.0.0 + PerMonitorV2) -> {target}"
        )
    else:
        print(f"[-] Failed to embed or verify RT_MANIFEST in {target}")
        sys.exit(1)
