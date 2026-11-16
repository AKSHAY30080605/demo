"""Supporting services: system info, capture, Cowrie ingest, bounded simulations.
All network-touching actions are restricted to local/private allowlisted targets
with strict duration and rate caps, per the project safety policy.
"""
import os, json, time, socket, threading, subprocess, ipaddress, random
import config
from database import get_db, add_security_event, audit

# ---------- system ----------
def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def system_info():
    info = {"cpu_percent": None, "ram_percent": None, "disk_percent": None,
            "temp_c": None, "hostname": socket.gethostname()}
    try:
        import psutil
        info["cpu_percent"] = psutil.cpu_percent(interval=0.2)
        info["ram_percent"] = psutil.virtual_memory().percent
        info["disk_percent"] = psutil.disk_usage(str(config.BASE_DIR)).percent
    except Exception:
        try:
            la = os.getloadavg()[0]; info["cpu_percent"] = round(la*25, 1)
        except Exception: pass
    # Pi CPU temperature if available
    try:
        p = "/sys/class/thermal/thermal_zone0/temp"
        if os.path.exists(p):
            info["temp_c"] = round(int(open(p).read().strip())/1000, 1)
    except Exception: pass
    return info

# ---------- capture ----------
# Real capture needs tcpdump/zeek + capture permission on the Pi. Where present we
# shell out; otherwise we DO NOT fabricate live traffic — we insert clearly marked
# demo flows (source='demo') so the pipeline is testable, never presented as live.
_CAP_JOBS = {}

def _tool_exists(name):
    from shutil import which
    return which(name) is not None

def capture_visibility_test(interface=None):
    interface = interface or config.CAPTURE_INTERFACE
    if not _tool_exists("tcpdump"):
        return {"visible": None, "reason": "tcpdump not installed (sudo apt install tcpdump)",
                "tool": None, "interface": interface}
    try:
        out = subprocess.run(["tcpdump", "-i", interface, "-c", "10", "-nn", "-q"],
                             capture_output=True, timeout=10, text=True)
        err = (out.stderr or "").strip()
        pkts = len([l for l in out.stdout.splitlines() if l.strip()])
        if "permission" in err.lower() or "Operation not permitted" in err:
            return {"visible": None, "tool": "tcpdump", "interface": interface,
                    "reason": "no capture permission — run: sudo setcap "
                              "cap_net_raw,cap_net_admin+ep $(which tcpdump)"}
        return {"visible": pkts > 0, "packets": pkts, "tool": "tcpdump",
                "interface": interface,
                "reason": f"captured {pkts} packets on {interface}" if pkts
                          else f"no packets seen on {interface} (is the stream active? "
                               "switched Wi-Fi hides other clients' traffic)"}
    except subprocess.TimeoutExpired:
        return {"visible": False, "tool": "tcpdump", "interface": interface,
                "reason": f"no packets within 10s on {interface}"}
    except Exception as e:
        return {"visible": None, "reason": str(e), "tool": "tcpdump", "interface": interface}


def _svc_from_port(port):
    return {22: "ssh", 23: "telnet", 53: "dns", 80: "http", 443: "ssl",
            554: "rtsp", 1935: "rtmp", 8081: "http", 8080: "http",
            2222: "ssh", 25: "smtp", 123: "ntp"}.get(int(port), "-")


def _pcap_to_flows(pcap_path, max_packets=60000):
    """Parse a pcap into Zeek-style conn flow records (real features, no fabrication).
    Groups packets by 5-tuple; first-seen side is the originator."""
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
    except Exception:
        return None  # scapy not available -> caller falls back
    flows = {}
    n = 0
    try:
        with PcapReader(pcap_path) as pr:
            for pkt in pr:
                n += 1
                if n > max_packets:
                    break
                l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if l3 is None:
                    continue
                src, dst = l3.src, l3.dst
                if pkt.haslayer(TCP):
                    proto = "tcp"; L = pkt.getlayer(TCP); sp, dp = int(L.sport), int(L.dport); flags = int(L.flags)
                elif pkt.haslayer(UDP):
                    proto = "udp"; L = pkt.getlayer(UDP); sp, dp = int(L.sport), int(L.dport); flags = 0
                elif pkt.haslayer(ICMP):
                    proto = "icmp"; sp, dp = 0, 0; flags = 0
                else:
                    continue
                iplen = int(getattr(l3, "len", 0) or getattr(l3, "plen", 0) or len(pkt))
                payload = max(0, iplen - 40)
                ts = float(pkt.time)
                key = tuple(sorted([(src, sp), (dst, dp)])) + (proto,)
                f = flows.get(key)
                if not f:
                    f = {"orig": (src, sp), "proto": proto, "t0": ts, "t1": ts,
                         "ob": 0, "rb": 0, "op": 0, "rp": 0, "oib": 0, "rib": 0,
                         "syn": False, "synack": False, "fin": False, "rst": False,
                         "dport": dp, "sport": sp}
                    flows[key] = f
                is_orig = (src, sp) == f["orig"]
                f["t1"] = max(f["t1"], ts)
                if is_orig:
                    f["op"] += 1; f["ob"] += payload; f["oib"] += iplen
                else:
                    f["rp"] += 1; f["rb"] += payload; f["rib"] += iplen
                if proto == "tcp":
                    if flags & 0x02 and not flags & 0x10: f["syn"] = True
                    if flags & 0x02 and flags & 0x10: f["synack"] = True
                    if flags & 0x01: f["fin"] = True
                    if flags & 0x04: f["rst"] = True
    except Exception:
        return None
    out = []
    for f in flows.values():
        established = f["synack"] or f["rp"] > 0
        if f["proto"] == "tcp":
            if f["rst"]: cs = "RSTO" if established else "REJ"
            elif f["fin"] and established: cs = "SF"
            elif established: cs = "S1"
            elif f["syn"]: cs = "S0"
            else: cs = "OTH"
        else:
            cs = "SF" if f["rp"] > 0 else "S0"
        server_port = min(f["sport"], f["dport"]) if f["dport"] else f["dport"]
        out.append({
            "duration": round(f["t1"] - f["t0"], 4),
            "orig_p": int(f["orig"][1]), "resp_p": int(f["dport"]),
            "orig_bytes": int(f["ob"]), "resp_bytes": int(f["rb"]),
            "orig_pkts": int(f["op"]), "resp_pkts": int(f["rp"]),
            "orig_ip_bytes": int(f["oib"]), "resp_ip_bytes": int(f["rib"]),
            "missed_bytes": 0, "proto": f["proto"],
            "service": _svc_from_port(server_port), "conn_state": cs,
        })
    return out

def _demo_flow(label_val):
    """Clearly-marked synthetic flow (source=demo). NOT live traffic."""
    abnormal = label_val == 1
    return {
        "duration": round(random.uniform(2, 6) if abnormal else random.uniform(0, 0.6), 4),
        "orig_p": random.randint(1024, 65535),
        "resp_p": random.choice([22, 23, 2222] if abnormal else [53, 80, 443]),
        "orig_bytes": random.randint(1500, 9000) if abnormal else random.randint(50, 500),
        "resp_bytes": random.randint(500, 3000) if abnormal else random.randint(0, 100),
        "orig_pkts": random.randint(30, 200) if abnormal else random.randint(1, 5),
        "resp_pkts": random.randint(10, 100) if abnormal else random.randint(0, 3),
        "orig_ip_bytes": random.randint(3000, 20000) if abnormal else random.randint(100, 1000),
        "resp_ip_bytes": random.randint(1000, 8000) if abnormal else random.randint(0, 200),
        "missed_bytes": random.randint(0, 50) if abnormal else 0,
        "proto": "tcp" if abnormal else "udp",
        "service": "ssh" if abnormal else "dns",
        "conn_state": "REJ" if abnormal else "S0",
    }

def _real_capture(session_id, interface, duration, label_val, job):
    """Capture live packets with tcpdump -> parse into real flow records with scapy.
    Returns True if real flows were stored; False to let caller fall back to demo."""
    if not _tool_exists("tcpdump"):
        return False
    pcap = os.path.join(config.CAPTURE_DIR, f"session_{session_id}.pcap")
    try:
        # -s 128 keeps headers (enough for flow features), -c caps packet count.
        proc = subprocess.Popen(
            ["tcpdump", "-i", interface, "-s", "128", "-c", "50000",
             "-w", pcap, "-nn"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        job["proc"] = proc
        waited = 0.0
        while waited < duration and not job["stop"] and proc.poll() is None:
            time.sleep(0.5); waited += 0.5
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: proc.kill()
        err = (proc.stderr.read() or b"").decode("replace") if proc.stderr else ""
        if "Operation not permitted" in err or "permission" in err.lower():
            job["error"] = ("no capture permission — run: sudo setcap "
                            "cap_net_raw,cap_net_admin+ep $(which tcpdump)")
            return False
    except Exception as e:
        job["error"] = f"tcpdump failed: {e}"
        return False
    if not os.path.exists(pcap) or os.path.getsize(pcap) < 40:
        job["error"] = "no packets captured (stream active? interface correct?)"
        return False
    flows = _pcap_to_flows(pcap)
    if flows is None:
        job["error"] = "scapy not installed — pip install scapy (using demo fallback)"
        return False
    with get_db() as con:
        for feat in flows:
            con.execute("INSERT INTO flows(session_id,timestamp,features_json,"
                        "label,source,schema_version) VALUES(?,?,?,?,?,?)",
                        (session_id, time.time(), json.dumps(feat), label_val,
                         "capture", "v1"))
            job["count"] += 1
    job["real"] = True
    return True


def start_capture(session_id, interface, duration, label):
    label_val = 1 if str(label).lower() in ("abnormal", "attack", "1") else 0
    job = {"stop": False, "count": 0, "real": False, "error": None}
    _CAP_JOBS[session_id] = job

    def run():
        ok = False
        try:
            ok = _real_capture(session_id, interface, duration, label_val, job)
        except Exception as e:
            job["error"] = str(e)
        if not ok:
            # Fallback: clearly-marked demo flows (source='demo'), never shown as live.
            t_end = time.time() + min(duration, 20)
            while time.time() < t_end and not job["stop"]:
                feat = _demo_flow(label_val)
                with get_db() as con:
                    con.execute("INSERT INTO flows(session_id,timestamp,features_json,"
                                "label,source,schema_version) VALUES(?,?,?,?,?,?)",
                                (session_id, time.time(), json.dumps(feat), label_val,
                                 "demo", "v1"))
                job["count"] += 1
                time.sleep(max(0.2, duration/40))
        src = "capture" if job["real"] else "demo"
        with get_db() as con:
            con.execute("UPDATE collection_sessions SET status='done',end_time=?,"
                        "flow_count=?,label_source=? WHERE id=?",
                        (time.time(), job["count"],
                         f"live_{src}", session_id))
    threading.Thread(target=run, daemon=True).start()

def stop_capture(session_id):
    job = _CAP_JOBS.get(session_id)
    if job: job["stop"] = True; return job["count"]
    with get_db() as con:
        r = con.execute("SELECT COUNT(*) c FROM flows WHERE session_id=?",
                        (session_id,)).fetchone()
    return r["c"]

# ---------- Cowrie ----------
def cowrie_status():
    """Detect Cowrie robustly across versions: the modern package runs as a
    `twistd ... cowrie` process, the old one as `bin/cowrie`. Fall back to a
    check on the SSH decoy port."""
    running = False; pid = None
    try:
        out = subprocess.run(["pgrep", "-f", "cowrie"], capture_output=True, text=True)
        for p in [x for x in out.stdout.split() if x.strip()]:
            try:
                cmd = open(f"/proc/{p}/cmdline").read().replace("\x00", " ")
            except Exception:
                continue
            if ("twistd" in cmd and "cowrie" in cmd) or "bin/cowrie" in cmd:
                running = True; pid = p; break
    except Exception:
        pass
    if not running:
        try:
            out = subprocess.run(["ss", "-tlnH"], capture_output=True, text=True)
            if f":{config.COWRIE_SSH_PORT} " in out.stdout.replace("\t", " "):
                running = True
        except Exception:
            pass
    return {"running": running, "pid": pid,
            "log_path": config.COWRIE_JSON_LOG,
            "log_exists": os.path.exists(config.COWRIE_JSON_LOG),
            "ssh_port": config.COWRIE_SSH_PORT,
            "telnet_port": config.COWRIE_TELNET_PORT}

_cowrie_offset_file = str(config.LOG_DIR / "cowrie_offset.txt")

def cowrie_ingest():
    path = config.COWRIE_JSON_LOG
    if not os.path.exists(path): return 0
    try:
        off = int(open(_cowrie_offset_file).read().strip())
    except Exception:
        off = 0
    n = 0
    with open(path, "r", errors="replace") as f:
        f.seek(off)
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            ts = ev.get("timestamp")
            try:
                et = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) if ts else time.time()
            except Exception:
                et = time.time()
            summary = _cowrie_summary(ev)
            with get_db() as con:
                con.execute("INSERT INTO cowrie_events(event_time,eventid,session,"
                            "src_ip,protocol,event_json,parsed_summary) VALUES(?,?,?,?,?,?,?)",
                            (et, ev.get("eventid", ""), ev.get("session", ""),
                             ev.get("src_ip", ""), ev.get("protocol", "ssh"),
                             json.dumps(ev), summary))
                con.execute("INSERT INTO security_events(event_time,event_source,"
                            "category,severity,source_ip,evidence_ref) VALUES(?,?,?,?,?,?)",
                            (et, "cowrie", ev.get("eventid", "honeypot_event"),
                             "medium", ev.get("src_ip", ""), ev.get("session", "")))
            n += 1
        off = f.tell()
    open(_cowrie_offset_file, "w").write(str(off))
    return n

def _cowrie_summary(ev):
    eid = ev.get("eventid", "")
    if eid == "cowrie.login.failed":
        return f"login failed user={ev.get('username')} pass=***"
    if eid == "cowrie.login.success":
        return f"login SUCCESS user={ev.get('username')}"
    if eid == "cowrie.command.input":
        return f"cmd: {ev.get('input','')[:120]}"
    if eid == "cowrie.session.connect":
        return f"connect from {ev.get('src_ip')}:{ev.get('src_port','')}"
    if eid == "cowrie.session.file_download":
        return f"file dl {ev.get('url','')[:80]}"
    return eid

# ---------- bounded simulation ----------
_SIM_JOBS = {}

def validate_lab_target(target):
    if not target:
        return False, "no target"
    if target in config.LAB_TARGET_ALLOWLIST:
        return True, "allowlisted"
    host = target.split(":")[0]
    if host in ("localhost",):
        return True, "localhost"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private:
            if host in config.LAB_TARGET_ALLOWLIST or ip.is_loopback:
                return True, "private/loopback"
            return False, f"{host} is private but not in allowlist {config.LAB_TARGET_ALLOWLIST}"
        return False, "public IPs are blocked by policy"
    except ValueError:
        return False, "target must be an allowlisted host or private/loopback IP"

# Throwaway test credentials used ONLY to probe your own Cowrie decoy so it logs them.
# These are generic honeypot-test values, never real accounts.
_DECOY_TEST_CREDS = [
    ("root", "123456"), ("admin", "admin"), ("root", "root"),
    ("user", "password"), ("admin", "1234"), ("pi", "raspberry"),
]

def _cowrie_login_attack(host, port, u, p):
    """One SSH login attempt against the LOCAL Cowrie decoy so it records the attempt.
    Uses paramiko if present; else a raw socket connect (Cowrie still logs the session).
    Always expected to 'fail' auth — that failure is the logged evidence."""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(host, port=port, username=u, password=p, timeout=4,
                      allow_agent=False, look_for_keys=False, banner_timeout=4,
                      auth_timeout=4)
            c.close()
        except Exception:
            pass   # auth failure / closed session is the expected, logged outcome
        return "paramiko"
    except ImportError:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0); s.connect_ex((host, port)); s.recv(64); s.close()
        except Exception:
            pass
        return "socket"


def start_simulation(run_id, scenario, target, duration, rate):
    """Bounded test-traffic generator against an allowlisted local target only.
    'cowrie_login' makes real login attempts at your OWN Cowrie decoy (so it logs
    them, closing the attack->honeypot->dashboard loop). All scenarios are capped in
    duration/rate and restricted to allowlisted local/private targets. Not a general
    attack tool; no payloads, no amplification, no public targets."""
    job = {"stop": False, "count": 0, "method": None}
    _SIM_JOBS[run_id] = job
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else (
        config.COWRIE_SSH_PORT if scenario == "cowrie_login" else config.COWRIE_SSH_PORT)

    def run():
        t_end = time.time() + duration
        interval = 1.0 / max(1, rate)
        ci = 0
        while time.time() < t_end and not job["stop"]:
            if scenario == "cowrie_login":
                u, p = _DECOY_TEST_CREDS[ci % len(_DECOY_TEST_CREDS)]; ci += 1
                job["method"] = _cowrie_login_attack(host, port, u, p)
                with get_db() as con:
                    con.execute("INSERT INTO security_events(event_time,event_source,"
                                "category,severity,source_ip,destination_ip,evidence_ref)"
                                " VALUES(?,?,?,?,?,?,?)",
                                (time.time(), "simulation", "decoy_login_attempt",
                                 "low", lan_ip(), host, f"sim{run_id}:{u}"))
            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5); s.connect_ex((host, port)); s.close()
                except Exception:
                    pass
                feat = _demo_flow(1)
                with get_db() as con:
                    con.execute("INSERT INTO flows(session_id,timestamp,features_json,"
                                "label,source,schema_version) VALUES(?,?,?,?,?,?)",
                                (None, time.time(), json.dumps(feat), 1,
                                 f"simulation:{scenario}", "v1"))
                    con.execute("INSERT INTO security_events(event_time,event_source,"
                                "category,severity,source_ip,destination_ip,evidence_ref)"
                                " VALUES(?,?,?,?,?,?,?)",
                                (time.time(), "simulation", scenario, "low",
                                 lan_ip(), host, f"sim{run_id}"))
            job["count"] += 1
            time.sleep(interval)
        # pull the fresh Cowrie logs so the attempts show on the Honeypot page
        if scenario == "cowrie_login":
            try: cowrie_ingest()
            except Exception: pass
        with get_db() as con:
            con.execute("UPDATE simulation_runs SET status='done',end_time=?,"
                        "event_count=? WHERE id=?", (time.time(), job["count"], run_id))
    threading.Thread(target=run, daemon=True).start()

def stop_simulation(run_id):
    job = _SIM_JOBS.get(run_id)
    if job: job["stop"] = True; return job["count"]
    return 0
