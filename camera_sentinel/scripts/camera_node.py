"""Camera / laptop NODE client: encrypt + authenticate + send an alert to the server.
Run this ON a camera node (Pi or laptop). It does NOT need the server's code — only
this file, the node_id, the master key (shown once at registration), and requests.

Usage:
  python scripts/camera_node.py --server https://<pi-ip>:8000 \
      --node cam01 --key <master_key_hex> \
      --event frozen_feed --severity high --variance 0.01

For a quick repeating demo:  add --loop 10  (sends 10 alerts, 2s apart)
"""
import os, sys, json, time, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_node as c
try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

def send(server, node, key, payload, verify_tls):
    tok = c.make_token(node, key)
    enc = c.encrypt_payload(node, key, json.dumps(payload).encode())
    body = {"node_id": node, **tok, **enc}
    r = requests.post(server.rstrip("/") + "/api/ingest", json=body,
                      timeout=10, verify=verify_tls)
    return r.status_code, r.text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--event", default="node_alert")
    ap.add_argument("--category", default=None)
    ap.add_argument("--severity", default="medium")
    ap.add_argument("--variance", type=float, default=None)
    ap.add_argument("--loop", type=int, default=1)
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verify (self-signed dashboard cert)")
    a = ap.parse_args()
    verify = False if (a.insecure or a.server.startswith("https")) else True
    if not verify:
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception: pass
    for i in range(a.loop):
        payload = {"event": a.event, "category": a.category or a.event,
                   "severity": a.severity, "ts": time.time()}
        if a.variance is not None:
            payload["variance"] = a.variance
        code, text = send(a.server, a.node, a.key, payload, verify)
        print(f"[{i+1}/{a.loop}] {code} {text}")
        if a.loop > 1:
            time.sleep(2)

if __name__ == "__main__":
    main()
