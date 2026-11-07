# -*- coding: utf-8 -*-
"""
report_generator.py — Standalone, Self-Contained HTML Security & Reverse Engineering Report Generator
Produces a zero-dependency, dark-themed, responsive single-file HTML report for offline presentation.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniReverse Security Audit — {{TARGET_NAME}}</title>
    <style>
        :root {
            --bg: #090d13;
            --surface: #121820;
            --surface-elevated: #1a222d;
            --border: rgba(255, 255, 255, 0.08);
            --border-highlight: rgba(32, 178, 170, 0.3);
            --teal: #20b2aa;
            --cyan: #38bdf8;
            --red: #ef4444;
            --amber: #f59e0b;
            --green: #10b981;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text-main);
            font-family: var(--font-sans);
            padding: 30px 20px;
            line-height: 1.5;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }
        .brand { font-size: 1.4rem; font-weight: 800; color: var(--teal); letter-spacing: -0.02em; }
        .meta-pill {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
        @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            overflow: hidden;
        }
        .card-title {
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--teal);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--text-muted); font-weight: 600; width: 35%; }
        td { color: var(--text-main); font-family: var(--font-mono); word-break: break-all; }
        .code-box {
            background: #05080c;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            color: var(--cyan);
            max-height: 320px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        .badge-clean { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid var(--green); }
        .badge-threat { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid var(--red); }
        .svg-container {
            width: 100%;
            overflow-x: auto;
            background: #05080c;
            border-radius: 8px;
            padding: 16px;
            border: 1px solid var(--border);
            text-align: center;
        }
        .svg-container svg { max-width: 100%; height: auto; }
        footer {
            margin-top: 40px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            font-size: 0.75rem;
            color: var(--text-muted);
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand">OmniReverse Studio v3.2</div>
                <div style="font-size:0.85rem; color:var(--text-muted);">Defensive Security & Reverse Engineering Audit</div>
            </div>
            <div class="meta-pill">Generated: {{TIMESTAMP}}</div>
        </header>

        <!-- Executive Summary -->
        <div class="grid-2">
            <div class="card">
                <div class="card-title">📦 Artifact Overview</div>
                <table>
                    <tr><th>Target Name</th><td>{{TARGET_NAME}}</td></tr>
                    <tr><th>Architecture</th><td>{{ARCH}}</td></tr>
                    <tr><th>File Size</th><td>{{FILE_SIZE}}</td></tr>
                    <tr><th>SHA-256</th><td style="font-size:0.75rem;">{{SHA256}}</td></tr>
                    <tr><th>Packer / Runtimes</th><td>{{PACKER_INFO}}</td></tr>
                </table>
            </div>

            <div class="card">
                <div class="card-title">🛡️ Threat & Crypto Triage</div>
                <table>
                    <tr><th>Entropy Score</th><td>{{ENTROPY}}</td></tr>
                    <tr><th>Direct Syscalls</th><td>{{SYSCALLS}}</td></tr>
                    <tr><th>S-Box Crypto Detections</th><td>{{CRYPTO_DETECTED}}</td></tr>
                    <tr><th>Status Verdict</th><td><span class="badge {{VERDICT_CLASS}}">{{VERDICT_LABEL}}</span></td></tr>
                </table>
            </div>
        </div>

        <!-- Visual CFG Section if available -->
        <div class="card" style="margin-bottom: 24px;">
            <div class="card-title">📊 Basic-Block Control Flow Graph (CFG)</div>
            <div class="svg-container">
                {{CFG_SVG}}
            </div>
        </div>

        <!-- Disassembly / Key Functions -->
        <div class="card" style="margin-bottom: 24px;">
            <div class="card-title">⚙️ Entry Disassembly & High-Entropy Instructions</div>
            <div class="code-box">{{DISASSEMBLY}}</div>
        </div>

        <!-- Strings & Extracted Indicators -->
        <div class="card">
            <div class="card-title">🔍 Extracted Indicators of Compromise (IoC) & Strings</div>
            <div class="code-box">{{STRINGS_OUTPUT}}</div>
        </div>

        <footer>
            OmniReverse Studio — Autonomous 42-Engine Multi-Architecture Reverse Engineering Platform &copy; 2026
        </footer>
    </div>
</body>
</html>"""


def generate_html_report(target_path: str, triage_data: Dict[str, Any], output_path: str = None) -> str:
    """Renders a self-contained, high-fidelity dark-themed HTML audit report."""
    p = Path(target_path)
    target_name = p.name if p.exists() else str(target_path)
    file_size = f"{p.stat().st_size:,} bytes" if p.exists() else "Unknown"

    sha256 = triage_data.get("sha256", "N/A")
    arch = triage_data.get("arch", triage_data.get("format", "x86_64 / PE / ELF"))
    entropy = str(round(triage_data.get("entropy", 0.0), 3))

    packer_info = triage_data.get("packer", "None detected (Plain)")
    syscalls = str(len(triage_data.get("syscalls", [])))
    crypto = ", ".join(triage_data.get("crypto", [])) or "None identified"

    is_threat = float(entropy) > 7.2 or bool(triage_data.get("syscalls"))
    verdict_class = "badge-threat" if is_threat else "badge-clean"
    verdict_label = "ELEVATED ENTROPY / PACKED" if is_threat else "STANDARD INTEGRITY"

    cfg_svg = triage_data.get("cfg_svg", '<div style="color:var(--text-muted); padding:20px;">CFG rendering bypassed for this artifact.</div>')
    disasm = triage_data.get("disasm", "No disassembly captured for this format.")
    strings_out = "\n".join(triage_data.get("strings", ["No suspicious strings identified."]))

    html = HTML_TEMPLATE
    html = html.replace("{{TARGET_NAME}}", target_name)
    html = html.replace("{{TIMESTAMP}}", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    html = html.replace("{{FILE_SIZE}}", file_size)
    html = html.replace("{{SHA256}}", sha256)
    html = html.replace("{{ARCH}}", arch)
    html = html.replace("{{PACKER_INFO}}", packer_info)
    html = html.replace("{{ENTROPY}}", entropy)
    html = html.replace("{{SYSCALLS}}", syscalls)
    html = html.replace("{{CRYPTO_DETECTED}}", crypto)
    html = html.replace("{{VERDICT_CLASS}}", verdict_class)
    html = html.replace("{{VERDICT_LABEL}}", verdict_label)
    html = html.replace("{{CFG_SVG}}", cfg_svg)
    html = html.replace("{{DISASSEMBLY}}", disasm)
    html = html.replace("{{STRINGS_OUTPUT}}", strings_out)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(html, encoding="utf-8")

    return html
