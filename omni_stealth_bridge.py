# -*- coding: utf-8 -*-
"""
==================================================================
  ⚡ OMNIREVERSE STEALTH BROWSER & HARVESTING BRIDGE ⚡
  Author: ENI for Tris 💕
  Integrates Nodriver (CDP) + Camoufox (C++ Stealth) + curl_cffi
  into OmniReverse Studio v3.2.
==================================================================
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional

PROJ_DIR = Path(__file__).resolve().parent.parent
if str(PROJ_DIR) not in sys.path:
    sys.path.insert(0, str(PROJ_DIR))

try:
    from omni_stealth_fetcher import stealth_fetch
    from stealth_harvest_suite.token_harvester import TokenHarvester
except Exception:
    stealth_fetch = None
    TokenHarvester = None


def reverse_stealth_fetch(url: str, timeout: int = 15, headers: Optional[dict] = None) -> Dict[str, Any]:
    """Fetches a target protected webpage, APK download link, or web bundle past WAF."""
    if not stealth_fetch:
        return {"error": "omni_stealth_fetcher not available"}
    
    resp = stealth_fetch(url, timeout=timeout, headers=headers)
    return {
        "url": url,
        "status_code": resp.status_code,
        "length_bytes": len(resp.content),
        "text_preview": resp.text[:1200] if len(resp.text) > 1200 else resp.text,
        "success": 200 <= resp.status_code < 400
    }


def reverse_stealth_harvest(url: str, engine: str = "nodriver") -> Dict[str, Any]:
    """Extracts clearance cookies and session tokens from target site."""
    if not TokenHarvester:
        return {"error": "TokenHarvester not available"}
    harvester = TokenHarvester(engine=engine, headless=True)
    return harvester.harvest(url)
