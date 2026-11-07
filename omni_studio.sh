#!/usr/bin/env bash
# OmniReverse Studio v2.1 — Cross-Platform POSIX Launcher (macOS / Linux)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PY_BIN="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY_BIN="python3"
else
  PY_BIN="python"
fi

MODE="${1:-web}"
shift || true

case "$MODE" in
  web)
    echo "[*] Starting OmniReverse Cross-Platform Web Studio at http://127.0.0.1:8765 ..."
    exec "$PY_BIN" "$SCRIPT_DIR/omni_web_studio.py" --host 127.0.0.1 --port 8765 "$@"
    ;;
  mcp)
    exec "$PY_BIN" "$SCRIPT_DIR/omni_server.py" "$@"
    ;;
  cli)
    exec "$PY_BIN" "$SCRIPT_DIR/omni_cli_runner.py" "$@"
    ;;
  test)
    exec "$PY_BIN" -m pytest -q "$@"
    ;;
  *)
    echo "Usage: ./omni_studio.sh [web|mcp|cli|test] [args...]"
    exit 1
    ;;
esac
