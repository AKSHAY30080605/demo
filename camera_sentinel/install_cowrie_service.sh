#!/usr/bin/env bash
# Install Cowrie honeypot as an auto-start systemd service.
# Run AFTER you have installed Cowrie (see services/cowrie/README_COWRIE.md).
# Usage:  sudo ./install_cowrie_service.sh  [cowrie_home]
# Default cowrie_home = /home/cowrie/cowrie
set -e
COWRIE_HOME="${1:-/home/cowrie/cowrie}"
COWRIE_USER="cowrie"

if [ ! -x "$COWRIE_HOME/bin/cowrie" ]; then
  echo "[!] Cowrie not found at $COWRIE_HOME/bin/cowrie"
  echo "    Install Cowrie first (services/cowrie/README_COWRIE.md),"
  echo "    or pass the correct path:  sudo ./install_cowrie_service.sh /path/to/cowrie"
  exit 1
fi

echo "[*] Installing Cowrie service (user=$COWRIE_USER, home=$COWRIE_HOME)"
sudo tee /etc/systemd/system/cowrie.service > /dev/null <<UNIT
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=$COWRIE_USER
Group=$COWRIE_USER
WorkingDirectory=$COWRIE_HOME
Environment=VIRTUAL_ENV=$COWRIE_HOME/cowrie-env
Environment=PATH=$COWRIE_HOME/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$COWRIE_HOME/bin/cowrie start
ExecStop=$COWRIE_HOME/bin/cowrie stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl restart cowrie
echo
echo "[✓] Cowrie will now start automatically on every boot."
echo "    Status : sudo systemctl status cowrie"
echo "    Logs   : sudo systemctl status cowrie ; tail -f $COWRIE_HOME/var/log/cowrie/cowrie.json"
echo "    Stop   : sudo systemctl stop cowrie"
