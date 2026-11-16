#!/usr/bin/env bash
# Camera Sentinel - install auto-start on boot (systemd).
# Auto-detects the current user and project path. Run with sudo.
set -e
USER_NAME="${SUDO_USER:-$(whoami)}"
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PY="$PROJ_DIR/venv/bin/python"

if [ ! -x "$VENV_PY" ]; then
  echo "[*] venv not found. Creating it and installing dependencies..."
  python3 -m venv "$PROJ_DIR/venv"
  "$PROJ_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$PROJ_DIR/venv/bin/pip" install --quiet -r "$PROJ_DIR/requirements.txt"
fi

echo "[*] Installing systemd service as user '$USER_NAME' from '$PROJ_DIR'"
sudo tee /etc/systemd/system/camera-sentinel.service > /dev/null <<UNIT
[Unit]
Description=Camera Sentinel - Secure Camera Network Analytics
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$PROJ_DIR
ExecStart=$VENV_PY $PROJ_DIR/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable camera-sentinel
sudo systemctl restart camera-sentinel
echo
echo "[✓] Auto-start installed. Camera Sentinel will now start on every boot."
echo "    Status : sudo systemctl status camera-sentinel"
echo "    Logs   : journalctl -u camera-sentinel -f"
echo "    Stop   : sudo systemctl stop camera-sentinel"
echo "    Disable: sudo systemctl disable camera-sentinel"
