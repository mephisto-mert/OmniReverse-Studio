"""Batch APK Analysis via OmniReverse Studio
Analyzes AI Wrapper APKs using the unified omni-reverse engine with portable CLI paths.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

STUDIO_DIR = Path(__file__).resolve().parent
if str(STUDIO_DIR) not in sys.path:
    sys.path.insert(0, str(STUDIO_DIR))

from pipeline import run_pipeline

DEFAULT_APK_POOL = STUDIO_DIR.parent / "ai_wrapper_apks"
DEFAULT_APK_NAMES = [
    "gh.xibai6668.android-ai-gateway.apk",
    "com.foss.aihub.apk",
    "gh.rhasan2026g-cell.groqchatbot.apk",
    "com.alxgnon.postwriter.apk",
    "com.jellodog.chat.apk",
    "gh.emadkhan031192.airkeys.apk",
    "com.essayness.essay_writer.apk",
    "net.canvoki.vokibot.apk",
    "com.editpad.essay_writer_app.apk",
    "gh.berpiztu.wslc-ai-agent.apk",
]


def discover_apks(apk_dir: Path, explicit_files: list[str] | None = None, limit: int = 10) -> list[Path]:
    if explicit_files:
        return [Path(p).resolve() for p in explicit_files if Path(p).is_file()]
    found: list[Path] = []
    for name in DEFAULT_APK_NAMES:
        cand = apk_dir / name
        if cand.is_file():
            found.append(cand)
    if not found and apk_dir.is_dir():
        found = sorted(apk_dir.glob("*.apk"))[:limit]
    return found[:limit]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OmniReverse Batch APK Analyzer")
    parser.add_argument("apks", nargs="*", help="Explicit APK file paths to analyze")
    parser.add_argument("--apk-dir", default=str(DEFAULT_APK_POOL), help="Directory containing target APKs")
    parser.add_argument("--output-dir", default=str(STUDIO_DIR / "batch_analysis_10_apks"), help="Output report directory")
    parser.add_argument("--limit", type=int, default=10, help="Maximum APKs to process")
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = discover_apks(Path(args.apk_dir).resolve(), args.apks, limit=max(1, args.limit))

    print(f"[*] Starting OmniReverse batch analysis on {len(targets)} AI APKs...")
    results = []

    for idx, apk_path in enumerate(targets, 1):
        size_mb = apk_path.stat().st_size / (1024 * 1024)
        print(f"\n[{idx}/{len(targets)}] Processing {apk_path.name} ({size_mb:.2f} MB)...")
        start_t = time.time()
        try:
            report = run_pipeline(str(apk_path), aggressive=True, beautify=True, export_base=str(out_dir))
            dur = time.time() - start_t

            report_md_path = out_dir / f"{apk_path.stem}_report.md"
            report_md_path.write_text(report.to_markdown(), encoding="utf-8")

            item = {
                "idx": idx,
                "apk_name": apk_path.name,
                "size_mb": round(size_mb, 2),
                "sha256": report.sha256[:16] + "...",
                "entropy": report.entropy,
                "obfuscators": report.obfuscators,
                "duration_sec": round(dur, 2),
                "export_dir": report.export_directory,
                "preview": report.decompiled_source[:500],
            }
            results.append(item)
            print(f"  [+] Success in {dur:.2f}s | Obfuscators: {report.obfuscators} | Export: {report.export_directory}")
        except Exception as exc:
            print(f"  [-] Failed on {apk_path.name}: {exc}")
            results.append({"idx": idx, "apk_name": apk_path.name, "error": str(exc)})

    summary_path = out_dir / "summary_results.json"
    summary_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Batch complete! Summary written to: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
