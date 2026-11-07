# -*- coding: utf-8 -*-
"""
OmniReverse AI Bridge (omni_llm_bridge.py)
Provides zero-friction AI decompilation, reverse engineering, and assembly analysis
using Hetzner Multi-Model Gateway (DeepSeek R1 / Claude 3.5/4.5 Sonnet / Groq Qwen Coder).
"""

import os
import sys
import io
import json
import urllib.request
import urllib.error

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

GATEWAY_URL = os.environ.get("OPENAI_BASE_URL", "").rstrip("/") + "/chat/completions" if os.environ.get("OPENAI_BASE_URL") else ""
API_KEY = os.environ.get("OPENAI_API_KEY", "")

DEFAULT_REASONING_MODEL = "deepseek-reasoner"
DEFAULT_FAST_MODEL = "qwen-3.8-coder"
DEFAULT_SWE_MODEL = "claude-sonnet-4-5"


def explain_code_snippet(code: str, language: str = "smali", model: str = DEFAULT_REASONING_MODEL) -> str:
    """
    Analyzes and explains decompiled assembly, smali, C/C++ or obfuscated JS.
    """
    sys_prompt = (
        "Sen kıdemli bir tersine mühendislik ve ikili dosya analiz uzmanısın. "
        "Verilen kaynak kod/assembly/smali bloğunu derinlemesine incele: "
        "1. Algoritmanın amacını ve şifreleme/hashing adımlarını açıkla. "
        "2. Gizli API anahtarları, endpoint'ler veya bypass noktalarını belirt. "
        "3. Temiz ve anlaşılır bir Python veya C pseudocode karşılığını ver."
    )
    
    user_prompt = f"Dil/Format: {language}\n\nKod Bloğu:\n```{language}\n{code[:8000]}\n```"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 2048,
        "temperature": 0.2
    }

    req = urllib.request.Request(
        GATEWAY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[!] OmniLLMBridge Hatası: {e}"


if __name__ == "__main__":
    test_smali = """
    .method public static checkLicense(Ljava/lang/String;)Z
        .registers 4
        const-string v0, "PREMIUM_USER_VIP"
        invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
        move-result v1
        return v1
    .end method
    """
    print("[*] Testing OmniLLMBridge with Hetzner Gateway (deepseek-reasoner)...")
    res = explain_code_snippet(test_smali, "smali")
    print(res[:300] + "...")
