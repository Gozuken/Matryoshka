#!/usr/bin/env bash
set -euo pipefail

# Simple deploy script for Ubuntu 20.04+/22.04
# Usage: sudo ./deploy_on_vps.sh <username> <repo_dir>

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <user> <repo_dir (absolute)>"
  exit 2
fi

USER="$1"
REPO_DIR="$2"

echo "Installing system dependencies..."
apt update
apt install -y python3 python3-venv python3-pip nodejs npm git ufw

echo "Setting up Python venv..."
cd "$REPO_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt || true

echo "Installing Node deps for directory server..."
cd "$REPO_DIR/directory-server"
npm install || true

echo "Creating systemd unit files..."
cp "$REPO_DIR/deploy/matryoshka-directory.service" /etc/systemd/system/matryoshka-directory.service
cp "$REPO_DIR/deploy/matryoshka-relay@.service" /etc/systemd/system/matryoshka-relay@.service
cp "$REPO_DIR/deploy/matryoshka-gateway.service" /etc/systemd/system/matryoshka-gateway.service

echo "Reloading systemd and enabling services..."
systemctl daemon-reload
systemctl enable --now matryoshka-directory.service
systemctl enable --now matryoshka-gateway.service || true

echo "Create example relay instances (3) and enable them..."
for i in 1 2 3; do
  systemctl enable --now matryoshka-relay@${i}.service || true
done

echo "UFW: allow directory port and example relay ports"
ufw allow 5000/tcp
ufw allow 8080/tcp
ufw allow 8001:8003/tcp
ufw --force enable

echo "Deployment complete. Check status with:"
echo "  sudo systemctl status matryoshka-directory"
echo "  sudo systemctl status matryoshka-relay@1"
