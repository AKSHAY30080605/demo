#!/usr/bin/env bash
# Camera Sentinel - resilient one-command launcher for Raspberry Pi.
# Handles flaky Wi-Fi/IPv6, retries downloads, and never leaves the venv inactive.
cd "$(dirname "$0")"
PROJ="$(pwd)"
PY=python3

# ---- 1. virtual environment ----
if [ ! -x "venv/bin/python" ]; then
  echo "[*] Creating virtual environment..."
  $PY -m venv venv || { echo "[!] venv creation failed. Run: sudo apt install -y python3-venv python3-full"; exit 1; }
fi
# Always use the venv's own python/pip by absolute path (never the system one).
VPY="$PROJ/venv/bin/python"
PIP="$VPY -m pip"

# ---- 2. pip settings for unstable networks ----
export PIP_DEFAULT_TIMEOUT=120
PIPFLAGS="--timeout 120 --retries 10 --prefer-binary"

echo "[*] Upgrading pip..."
$PIP install --upgrade pip $PIPFLAGS >/dev/null 2>&1 || echo "[i] pip upgrade skipped (continuing)."

# ---- 3. install CORE deps, retrying the whole set through network drops ----
install_set() {
  local file="$1" label="$2" tries=6 i
  for i in $(seq 1 $tries); do
    echo "[*] Installing $label dependencies (attempt $i/$tries)..."
    if $PIP install -r "$file" $PIPFLAGS; then
      echo "[✓] $label dependencies installed."
      return 0
    fi
    echo "[!] Network hiccup during $label install. Retrying in 6s..."
    sleep 6
  done
  return 1
}

if ! install_set requirements.txt "core"; then
  echo "[!] Core dependencies did not finish — this is a NETWORK problem, not the app."
  echo "    Your Pi keeps dropping the connection to PyPI. Try this, then re-run ./start.sh:"
  echo "      sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1"
  echo "      sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1"
  echo "    (prefer a wired/stable connection if you can)."
  exit 1
fi

# ---- 4. optional deps: best-effort, never block the app ----
if [ -f requirements-optional.txt ]; then
  install_set requirements-optional.txt "optional" || \
    echo "[i] Optional deps incomplete — app still runs (parquet/node-client/cowrie-attack may be limited)."
fi

# ---- 5. optional HTTPS cert ----
if [ "$CS_HTTPS" = "1" ] && { [ ! -f data/tls_cert.pem ] || [ ! -f data/tls_key.pem ]; }; then
  echo "[*] Generating self-signed TLS certificate..."
  $VPY scripts/gen_cert.py || echo "[i] cert generation skipped."
fi

# ---- 6. database + launch ----
echo "[*] Initialising database..."
$VPY database.py
echo "[*] Starting Camera Sentinel..."
exec $VPY app.py
