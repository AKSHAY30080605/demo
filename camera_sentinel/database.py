"""SQLite schema + helpers. Schema created automatically on first launch."""
import sqlite3, json, time, threading
from contextlib import contextmanager
import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, source TEXT, file_path TEXT,
  format TEXT, rows INTEGER, columns INTEGER, schema_version TEXT,
  created_at REAL, checksum TEXT, inspect_json TEXT);
CREATE TABLE IF NOT EXISTS dataset_columns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, dataset_id INTEGER, column_name TEXT,
  inferred_type TEXT, missing_count INTEGER, unique_count INTEGER,
  selected_for_model INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS collection_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, interface TEXT,
  scenario TEXT, label TEXT, label_source TEXT, start_time REAL, end_time REAL,
  notes TEXT, status TEXT, flow_count INTEGER DEFAULT 0,
  capture_path TEXT, export_path TEXT);
CREATE TABLE IF NOT EXISTS flows(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, timestamp REAL,
  features_json TEXT, label INTEGER, source TEXT, schema_version TEXT,
  raw_record_ref TEXT);
CREATE TABLE IF NOT EXISTS models(
  id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, model_path TEXT,
  feature_schema TEXT, target TEXT, dataset_ids TEXT, split_method TEXT,
  metrics_json TEXT, threshold REAL, created_at REAL, active INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS predictions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_time REAL, flow_ref TEXT,
  model_version TEXT, predicted_label INTEGER, abnormal_score REAL,
  threshold REAL, analyst_label INTEGER);
CREATE TABLE IF NOT EXISTS cowrie_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_time REAL, eventid TEXT,
  session TEXT, src_ip TEXT, protocol TEXT, event_json TEXT, parsed_summary TEXT);
CREATE TABLE IF NOT EXISTS security_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_time REAL, event_source TEXT,
  category TEXT, severity TEXT, source_ip TEXT, destination_ip TEXT,
  model_score REAL, model_version TEXT, session_id TEXT, evidence_ref TEXT,
  acknowledged INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS simulation_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scenario TEXT, target TEXT,
  start_time REAL, end_time REAL, parameters_json TEXT, status TEXT,
  event_count INTEGER DEFAULT 0, safety_confirmation INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_time REAL, action TEXT,
  object_type TEXT, object_id TEXT, details_json TEXT);
CREATE TABLE IF NOT EXISTS nodes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT UNIQUE, master_key TEXT,
  description TEXT, created_at REAL, last_seen REAL, status TEXT DEFAULT 'active',
  payload_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS node_payloads(
  id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, event_time REAL,
  category TEXT, decrypted_summary TEXT, src_ip TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS ix_flows_sess ON flows(session_id);
CREATE INDEX IF NOT EXISTS ix_sec_time ON security_events(event_time);
CREATE INDEX IF NOT EXISTS ix_sec_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS ix_cow_time ON cowrie_events(event_time);
CREATE INDEX IF NOT EXISTS ix_cow_ip ON cowrie_events(src_ip);
"""

@contextmanager
def get_db():
    con = sqlite3.connect(config.DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA journal_mode=WAL")
    try:
        yield con
        con.commit()
    finally:
        con.close()

def init_db():
    with _lock, get_db() as con:
        con.executescript(SCHEMA)
        cur = con.execute("SELECT v FROM settings WHERE k='initialized'")
        if not cur.fetchone():
            con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('initialized',?)",
                        (str(time.time()),))
            con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('threshold',?)",
                        (str(config.DEFAULT_THRESHOLD),))

def audit(action, object_type="", object_id="", details=None):
    with _lock, get_db() as con:
        con.execute("INSERT INTO audit_log(event_time,action,object_type,object_id,details_json)"
                    " VALUES(?,?,?,?,?)",
                    (time.time(), action, object_type, str(object_id),
                     json.dumps(details or {})))

def add_security_event(**kw):
    kw.setdefault("event_time", time.time())
    cols = ",".join(kw.keys()); ph = ",".join("?"*len(kw))
    with _lock, get_db() as con:
        con.execute(f"INSERT INTO security_events({cols}) VALUES({ph})", tuple(kw.values()))

def get_setting(k, default=None):
    with get_db() as con:
        r = con.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

def set_setting(k, v):
    with _lock, get_db() as con:
        con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, str(v)))

if __name__ == "__main__":
    init_db(); print("DB initialised at", config.DB_PATH)
