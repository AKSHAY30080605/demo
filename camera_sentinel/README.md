# Camera Sentinel — AI-Powered Secure Camera Network Analytics

A single, integrated local-first security analytics platform for a **Raspberry Pi 4 (4 GB, Raspberry Pi OS 64-bit)**:
network-flow IDS with **XGBoost**, a **Dataset Studio**, a bounded **Attack Simulation Lab**, and a same-Pi isolated **Cowrie honeypot** — all behind one dashboard, one database, one launch command.

> Research/prototype IDS. It does **not** guarantee every camera compromise is detected, and it does not
> claim to see all Wi-Fi traffic unless capture visibility is verified. Keep it on your private LAN. Never
> expose it to the Internet.

---

## 0. Quick start on the Pi (via SSH)

From your laptop:
```bash
ssh pi@<raspberry-pi-ip>        # or ssh pi@raspberrypi.local
```

On the Pi:
```bash
# 1. System packages
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump git

# 2. Copy the project to the Pi (one of these)
#    a) from your laptop:  scp camera_sentinel.zip pi@<pi-ip>:~
#    b) then on the Pi:
unzip camera_sentinel.zip
cd camera_sentinel

# 3. One command: creates venv, installs deps, builds DB, starts the app
chmod +x start.sh
./start.sh
```

The startup banner prints three URLs. Open one in a browser **on the same LAN**:
```
Dashboard : http://camera.local:8000      (only if mDNS works on your network)
LAN access: http://<pi-ip>:8000           (always works)
Local     : http://127.0.0.1:8000
```

**First run:** the page asks you to create an admin password (min 8 chars). That's it.

Stop the app with `Ctrl+C`.

---

### Install troubleshooting (flaky Wi-Fi / IPv6)
`start.sh` retries downloads automatically. If pip keeps dropping with
`SSL: UNEXPECTED_EOF` or `RemoteDisconnected`, your Pi is losing its connection to
PyPI (often IPv6). Force IPv4 for the session, then re-run `./start.sh`:
```bash
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
```
Also make sure the venv is active — the prompt should show `(venv)`. If not:
`source venv/bin/activate`. A wired connection is the most reliable.

## 1. Give tcpdump capture permission (for real traffic, no root)
```bash
sudo setcap cap_net_raw,cap_net_admin+ep $(which tcpdump)
```
Then use **Camera & Network Monitor → Run visibility test**. If no packets are seen, the Pi
cannot see that traffic on your network (normal switched Wi-Fi hides other clients' unicast).
Options: terminate the camera stream on the Pi, enable router/AP port-mirroring, or capture on the
laptop and forward flow records.

---

## 2. Train on the full IoT-SFC v2 dataset (your own data)

The full dataset (Zenodo DOI 10.5281/zenodo.23371775) is **42M rows / 12.63 GB** uncompressed —
far too big to load on a 4 GB Pi. Build a Pi-sized, balanced subset first:

```bash
# download + unzip the full CSV (on a machine with disk space)
#   iot_dataset_v7.zip -> iot_dataset_v7.csv  (12.63 GB)

# inside the project venv:
source venv/bin/activate

# chunk-read the giant CSV and keep ~60k rows per attack type (conn records only):
python scripts/prepare_dataset.py /path/to/iot_dataset_v7.csv \
    --out data/collected/iotsfc_subset.csv \
    --per-class 60000 --chunk 200000 --conn-only
```

Then in the dashboard:
1. **Dataset Management → Upload & Inspect** the subset CSV. You get the full inspection report
   (rows, columns, types, missingness, duplicates, label candidates, class distribution).
2. **Model Training →** pick the dataset and your options:
   - **Target:** `attack` (binary 0/1) or `type_of_attack` (14-class multiclass).
   - **Feature set:** canonical schema (recommended) or custom pick.
   - **Split:** stratified / group (by `uid`) / time (by `ts`) — group/time avoid leakage.
   - **Row cap**, test size, `n_estimators`, `max_depth`, `learning_rate`, class weighting.
   - Start → watch the live log → metrics appear (confusion matrix, precision/recall/F1, ROC/PR-AUC).
3. **Model Evaluation →** review and **Activate** the model.
4. **Live AI Detection →** score newly collected flows against the active model.

CLI alternative:
```bash
python scripts/train_model.py data/collected/iotsfc_subset.csv \
    --target attack --split group --class-weight --rows 150000
```

> The uploaded sample `DATASET.xlsx` is only 12 rows and all one class (`normal`) — good for schema
> study, but a usable model needs both normal **and** abnormal labelled flows (use the subset above,
> or collect your own labelled abnormal sessions).

---

## 3. Cowrie honeypot (same Pi, isolated)

See **`services/cowrie/README_COWRIE.md`** for the full isolated install (separate `cowrie` user,
decoy ports 2222/2223, JSON logging). Point the app at Cowrie's JSON log:
```bash
export CS_COWRIE_LOG=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```
The **Honeypot Monitoring** page tails and parses that JSON (passwords masked). To try the parser
without Cowrie, copy the included sample:
```bash
cp services/cowrie/cowrie.json.sample services/cowrie/cowrie.json
```

---

## 4. Attack Simulation Lab (safe & bounded)

Generates **bounded** test traffic only against **allowlisted local/private** targets, with hard
duration/rate caps. Public IPs, broadcast/multicast and the camera's production IP are blocked.
Edit the allowlist in `config.py` (`LAB_TARGET_ALLOWLIST`) or via `CS_LAB_ALLOWLIST`.

---

## 4b. Encryption — HTTPS dashboard + encrypted node ingest

**A) HTTPS for the dashboard** (encrypts login + all data on the LAN):
```bash
source venv/bin/activate
python scripts/gen_cert.py          # one-time self-signed cert
CS_HTTPS=1 ./start.sh               # now serves https://<pi-ip>:8000
```
Browsers warn once on a self-signed cert — accept to proceed. To make HTTPS permanent
with systemd, add `Environment=CS_HTTPS=1` under `[Service]` in the service file.

**B) Encrypted + authenticated node ingest** (camera/laptop nodes → server):
Each node sends **AES-256-GCM encrypted** alerts with a **time-bound, single-use HMAC
token** (captured tokens can't be replayed; revoked nodes are rejected).

1. Dashboard → **Secure Node Ingest** → *Register a Node* (e.g. `cam01`). Copy the master
   key shown **once**.
2. On the camera/laptop node, send an encrypted alert (needs only `scripts/camera_node.py`,
   `crypto_node.py`, and `requests`):
```bash
python scripts/camera_node.py --server https://<pi-ip>:8000 \
    --node cam01 --key <master_key> --event frozen_feed --severity high --insecure
```
3. The decrypted alert appears on the **Secure Node Ingest** page and in Security Events.
   `--insecure` skips TLS verification for the self-signed dashboard cert.

Crypto details: subkeys are derived from the master key
(`enc = HMAC(master,"enc")`, `mac = HMAC(master,"mac")`), so the raw master never
travels and encryption/authentication keys are separated. Token window is 30 s.

## 5. Auto-start on boot (one command)

Run the included installer — it auto-detects your user and project path, so there is
nothing to edit:
```bash
cd ~/camera_sentinel
sudo ./install_service.sh
```
After this, Camera Sentinel starts automatically every time the Pi powers on. Manage it with:
```bash
sudo systemctl status camera-sentinel     # is it running?
journalctl -u camera-sentinel -f          # live logs
sudo systemctl stop camera-sentinel       # stop now
sudo systemctl disable camera-sentinel    # turn off auto-start
```
Open the dashboard the same way: `http://<pi-ip>:8000` from any device on the LAN.

---

## 6. Stop / update / backup / restore

```bash
# stop (foreground)        Ctrl+C
# stop (systemd)           sudo systemctl stop camera-sentinel
# update deps              source venv/bin/activate && pip install -r requirements.txt
# backup DB                cp data/camera_sentinel.db  backup_$(date +%F).db
# restore DB               cp backup_YYYY-MM-DD.db  data/camera_sentinel.db
```

---

## Dashboard pages
1. Security Overview · 2. Camera & Network Monitor · 3. Traffic Collection Studio ·
4. Dataset Management · 5. Dataset Labelling · 6. Feature & Schema Studio · 7. Model Training ·
8. Model Evaluation · 9. Live AI Detection · 10. Attack Simulation Lab · 11. Honeypot Monitoring ·
12. Security Events & Logs · 13. Threat Correlation · 14. Reports & Analytics · 15. Settings & System Health.

## Configuration
All settings live in `config.py` and can be overridden with `CS_*` environment variables
(see `config.example.env`). Key ones: `CS_PORT`, `CS_IFACE`, `CS_COWRIE_LOG`, `CS_LAB_ALLOWLIST`.

## Project layout
```
camera_sentinel/
  app.py            main Flask app (pages + REST API)
  config.py         all settings
  database.py       SQLite schema + helpers
  ml_pipeline.py    XGBoost train / evaluate / inference (leak-safe bundle)
  services_mod.py   system info, capture, Cowrie ingest, bounded simulation
  start.sh          one-command launcher
  requirements.txt
  templates/        15 dashboard pages + base + login
  static/css, js/   dark cyber UI
  scripts/          inspect_dataset, prepare_dataset, train_model, evaluate_model,
                    collect_flows, cowrie_ingest
  services/cowrie/  Cowrie install guide + sample JSON
  data/             db, uploads, captures, collected, models, reports
  logs/
```

## Safety & honesty rules enforced
- Demo/synthetic flows are stored with `source='demo'` and never presented as live captures.
- No model → the UI says "Model not trained/deployed", never a fake risk score.
- Accuracy is never shown alone; class counts + split method accompany every model; small/single-class
  test sets are flagged.
- Honeypot contact and IDS detection are shown as **separate** sources; correlation (IP + time) never
  asserts "same attacker" as fact.
- Dashboard binds to the LAN with an admin password; Cowrie stays isolated from the real camera.
