#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="$ROOT/logs/pids"

if [[ ! -d "$PID_DIR" ]]; then
  echo "No pid dir found: $PID_DIR"
  exit 0
fi

for pidfile in "$PID_DIR"/*.pid; do
  [[ -e "$pidfile" ]] || continue
  pid="$(head -n 1 "$pidfile" || true)"
  name="$(basename "$pidfile")"

  if [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo "Stopping $name (PID $pid)"
    kill "$pid" 2>/dev/null || true
  fi

  rm -f "$pidfile"
done

echo "Done."
