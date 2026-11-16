"""Standalone capture helper. On the Pi this would drive Zeek/tcpdump.
Here it documents the intended command and calls the app's capture service.
Usage: python scripts/collect_flows.py --iface eth0 --seconds 60 --label normal
"""
import sys, os, argparse, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config, services_mod as svc, database as db
db.init_db()
ap = argparse.ArgumentParser()
ap.add_argument("--iface", default=config.CAPTURE_INTERFACE)
ap.add_argument("--seconds", type=int, default=60)
ap.add_argument("--label", default="normal")
a = ap.parse_args()
print("Capture visibility:", svc.capture_visibility_test(a.iface))
with db.get_db() as con:
    sid = con.execute("INSERT INTO collection_sessions(device_id,interface,scenario,"
        "label,label_source,start_time,status) VALUES(?,?,?,?,?,?,?)",
        ("cli", a.iface, "cli", a.label, "scripted_test", time.time(), "running")).lastrowid
svc.start_capture(sid, a.iface, a.seconds, a.label)
time.sleep(a.seconds+1)
print("session", sid, "done")
