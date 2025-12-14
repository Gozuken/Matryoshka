#!/usr/bin/env bash
set -euo pipefail

DIRECTORY_PORT="${DIRECTORY_PORT:-5000}"
DIRECTORY_HOST="${DIRECTORY_HOST:-0.0.0.0}"
RELAY_COUNT="${RELAY_COUNT:-3}"
RELAY_BASE_PORT="${RELAY_BASE_PORT:-8001}"
ADVERTISE_IP="${ADVERTISE_IP:-127.0.0.1}"
DLL_DIR="${DLL_DIR:-./dlls}"
LOG_DIR="${LOG_DIR:-./logs}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/$LOG_DIR/pids"

# If you run on Linux, you likely have libmatryoshka.so instead of DLL.
# Keep the env var name consistent.
if [[ -f "$ROOT/$DLL_DIR/libmatryoshka.so" ]]; then
  export MATRYOSHKA_DLL_PATH="$ROOT/$DLL_DIR/libmatryoshka.so"
fi

# Ensure dependent libs can be found
export LD_LIBRARY_PATH="$ROOT/$DLL_DIR:${LD_LIBRARY_PATH:-}"

echo "Root:        $ROOT"
echo "Directory:   http://$ADVERTISE_IP:$DIRECTORY_PORT"
echo "Relays:      $RELAY_COUNT (ports $RELAY_BASE_PORT..$((RELAY_BASE_PORT + RELAY_COUNT - 1)))"
echo "AdvertiseIp: $ADVERTISE_IP"
echo "Logs:        $ROOT/$LOG_DIR"

# Directory server
(
  cd "$ROOT/directory-server"
  PORT="$DIRECTORY_PORT" nohup node directory_server.js >"$ROOT/$LOG_DIR/directory-server.log" 2>&1 &
  echo $! >"$ROOT/$LOG_DIR/pids/directory-server.pid"
)

# Relays
for i in $(seq 1 "$RELAY_COUNT"); do
  relay_id="relay_${i}"
  relay_port=$((RELAY_BASE_PORT + i - 1))

  (
    cd "$ROOT/relay"
    nohup python relay_node.py \
      --id "$relay_id" \
      --port "$relay_port" \
      --directory "http://$ADVERTISE_IP:$DIRECTORY_PORT" \
      --ip "$ADVERTISE_IP" \
      >"$ROOT/$LOG_DIR/${relay_id}.log" 2>&1 &
    echo $! >"$ROOT/$LOG_DIR/pids/${relay_id}.pid"
  )
done

echo "Done. Stop with: $ROOT/scripts/stop.sh"
