#!/usr/bin/env bash
# Start directory server on 0.0.0.0:5000 and 20 relays on 0.0.0.0:8000..8019
set -euo pipefail

ADVERTISE_IP=${ADVERTISE_IP:-127.0.0.1}
DIRECTORY_PORT=${DIRECTORY_PORT:-5000}
RELAY_COUNT=${RELAY_COUNT:-20}
RELAY_BASE_PORT=${RELAY_BASE_PORT:-8000}
LOG_DIR=${LOG_DIR:-./logs/20-relays}
DLL_DIR=${DLL_DIR:-./dlls}

mkdir -p "$LOG_DIR" "$LOG_DIR/pids"

export PORT="$DIRECTORY_PORT"
export MATRYOSHKA_DLL_PATH="$DLL_DIR/Matryoshka.dll"
export PATH="$DLL_DIR:$PATH"

echo "Starting directory server on 0.0.0.0:$DIRECTORY_PORT (logs: $LOG_DIR/directory-server.log)"
nohup node directory-server/directory_server.js > "$LOG_DIR/directory-server.log" 2>&1 &
DIR_PID=$!
echo $DIR_PID > "$LOG_DIR/pids/directory-server.pid"

sleep 1

echo "Starting $RELAY_COUNT relays on ports $RELAY_BASE_PORT..$((RELAY_BASE_PORT + RELAY_COUNT - 1))"
for i in $(seq 0 $((RELAY_COUNT - 1))); do
  idx=$((i + 1))
  relay_id="relay_$idx"
  relay_port=$((RELAY_BASE_PORT + i))
  relay_log="$LOG_DIR/$relay_id.log"
  relay_pidfile="$LOG_DIR/pids/$relay_id.pid"

  echo "Starting $relay_id on 0.0.0.0:$relay_port (registering with http://$ADVERTISE_IP:$DIRECTORY_PORT)"
  nohup python relay/relay_node.py --id "$relay_id" --port "$relay_port" --directory "http://$ADVERTISE_IP:$DIRECTORY_PORT" --ip "$ADVERTISE_IP" > "$relay_log" 2>&1 &
  echo $! > "$relay_pidfile"
  sleep 0.15
done

echo "Done. Logs: $LOG_DIR"
echo "Stop with: ./scripts/stop.ps1 (Windows) or kill \\$(cat $LOG_DIR/pids/*.pid)"