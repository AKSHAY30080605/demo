# Cowrie honeypot on the SAME Raspberry Pi (isolated)

Cowrie is a separate, restricted SSH/Telnet decoy service. It runs on this same Pi
under its own unprivileged user and its own data directory. It is NOT the real camera
and must never be given access to the camera, SSH keys, or personal files.

## 1. Create an isolated user
```
sudo adduser --disabled-password --gecos "" cowrie
```

## 2. Install Cowrie (as the cowrie user)
```
sudo su - cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Configure (keep admin SSH on port 22 untouched)
```
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```
Edit etc/cowrie.cfg:
- `[ssh]` listen_endpoints = tcp:2222:interface=0.0.0.0   # decoy SSH on 2222
- `[telnet]` enabled = true, listen_endpoints = tcp:2223:interface=0.0.0.0
- `[output_jsonlog]` enabled = true
  logfile = /home/cowrie/cowrie/var/log/cowrie/cowrie.json

## 4. Point Camera Sentinel at the JSON log
In the Camera Sentinel project, set the env var (or edit config.py):
```
export CS_COWRIE_LOG=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```
(Default in config.py is services/cowrie/cowrie.json — symlink it if you prefer:
`ln -s /home/cowrie/cowrie/var/log/cowrie/cowrie.json  <project>/services/cowrie/cowrie.json`)

## 5. Start Cowrie
```
bin/cowrie start      # as the cowrie user
```

## 6. Generate a SAFE test interaction (from your laptop on the lab LAN)
```
ssh -p 2222 root@<pi-ip>     # try any password; Cowrie records it
```
The attempt appears on the Honeypot Monitoring page after ingest.

## Isolation rules (enforced by policy)
- Never run Cowrie as root.
- Restrict outbound access from the cowrie user (firewall / no egress).
- Do not proxy Cowrie to a real shell or the real camera.
- Admin SSH stays on port 22, separate and secured.
