"""Tail Cowrie JSON log into SQLite. Usage: python scripts/cowrie_ingest.py [--watch]"""
import sys, os, time, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database as db, services_mod as svc
db.init_db()
ap = argparse.ArgumentParser(); ap.add_argument("--watch", action="store_true")
a = ap.parse_args()
while True:
    n = svc.cowrie_ingest(); print(f"ingested {n} events")
    if not a.watch: break
    time.sleep(5)
