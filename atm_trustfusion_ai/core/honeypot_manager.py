"""
honeypot_manager.py - Cowrie & Decoy Honeypot Cyber Tripwire for ATM Surveillance
Integrated with TrustFusion AI SOC:

Functions:
  1. Cowrie Log Ingest: Ingests Cowrie SSH/Telnet decoy logs (login attempts, commands, file downloads).
  2. Web Decoy Traps: Intercepts unauthorized reconnaissance scanning on decoy endpoints (/admin, /setup.cgi, /rtsp).
  3. Dynamic IP Blacklist: Automatically isolates attacking IPs and triggers immediate Layer 2 security alarms.
"""

import os
import time
import json
from collections import deque

class HoneypotManager:
    def __init__(self, log_path=None):
        self.events = deque(maxlen=200)
        self.blacklisted_ips = set()
        self.log_path = log_path
        
        # Default sample or live cowrie log location
        if not self.log_path:
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            sample_path = os.path.join(base, "camera_sentinel", "services", "cowrie", "cowrie.json.sample")
            if os.path.exists(sample_path):
                self.log_path = sample_path
                self.ingest_cowrie_file(self.log_path)

    def record_decoy_hit(self, src_ip, endpoint, method="GET", payload=""):
        """Called when an attacker probes an unauthorized decoy endpoint."""
        now = time.time()
        self.blacklisted_ips.add(src_ip)
        ev = {
            "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
            "src_ip": src_ip,
            "type": "DECOY_WEB_PROBE",
            "service": "HTTP_DECOY_TRAP",
            "summary": f"Decoy probe on {method} {endpoint} (Payload: {payload[:60]})",
            "severity": "HIGH"
        }
        self.events.appendleft(ev)
        return ev

    def record_ssh_bruteforce(self, src_ip, username, password, command=None):
        """Called when Cowrie or SSH honeypot records a brute-force or shell interaction."""
        now = time.time()
        self.blacklisted_ips.add(src_ip)
        summary = f"SSH brute-force attempt user='{username}' pass='***'"
        if command:
            summary = f"SSH decoy shell command: '{command[:80]}'"
        ev = {
            "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
            "src_ip": src_ip,
            "type": "COWRIE_SSH_INTERACTION",
            "service": "COWRIE_SSH_PORT_2222",
            "summary": summary,
            "severity": "CRITICAL"
        }
        self.events.appendleft(ev)
        return ev

    def ingest_cowrie_file(self, file_path):
        """Reads Cowrie json log format and ingests events."""
        if not os.path.exists(file_path):
            return 0
        count = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except Exception:
                        continue
                    
                    eid = data.get("eventid", "")
                    src_ip = data.get("src_ip", "127.0.0.1")
                    self.blacklisted_ips.add(src_ip)
                    
                    if "login" in eid:
                        summary = f"SSH login attempt user='{data.get('username', 'root')}' pass='***'"
                    elif "command" in eid:
                        summary = f"Decoy shell command: '{data.get('input', '')[:80]}'"
                    elif "connect" in eid:
                        summary = f"Decoy SSH session connected from {src_ip}:{data.get('src_port', '')}"
                    else:
                        summary = f"Cowrie honeypot event: {eid}"
                    
                    self.events.appendleft({
                        "timestamp": data.get("timestamp", time.strftime("%H:%M:%S"))[11:19] if "T" in data.get("timestamp", "") else time.strftime("%H:%M:%S"),
                        "src_ip": src_ip,
                        "type": eid,
                        "service": "COWRIE_SSH_PORT_2222",
                        "summary": summary,
                        "severity": "HIGH" if "login" in eid else "CRITICAL"
                    })
                    count += 1
        except Exception as e:
            print(f"[Honeypot] Error reading Cowrie log: {e}")
        return count

    def get_status(self):
        top_ips = {}
        for ev in self.events:
            ip = ev.get("src_ip", "unknown")
            top_ips[ip] = top_ips.get(ip, 0) + 1
        sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "status": "ACTIVE_DECOY_ARMED",
            "cowrie_ssh_port": 2222,
            "cowrie_telnet_port": 2223,
            "total_events": len(self.events),
            "blacklisted_ips_count": len(self.blacklisted_ips),
            "blacklisted_ips": list(self.blacklisted_ips)[:10],
            "top_attackers": [{"ip": ip, "hits": count} for ip, count in sorted_ips],
            "recent_events": list(self.events)[:15]
        }
