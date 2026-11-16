"""Camera Sentinel - single integrated Flask application.
One entry point, one SQLite DB, 15 dashboard pages + REST API.
Run:  python app.py   (or ./start.sh)
"""
import os, sys, json, time, glob, pickle, threading, logging, shutil, hashlib
import sqlite3
from functools import wraps
from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, session, send_file, abort)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config, database as db
from database import get_db, audit, add_security_event, get_setting, set_setting
import ml_pipeline as ml
from scripts.inspect_dataset import inspect as inspect_file
import services_mod as svc   # cowrie + sysinfo + simulation helpers
import crypto_node as cnode  # encrypted + authenticated node ingest

logging.basicConfig(
    filename=str(config.LOG_DIR / "application.log"), level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("camera_sentinel")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # 2 GB upload cap

ALLOWED_EXT = {".csv", ".tsv", ".json", ".parquet", ".xlsx", ".xls", ".zip"}

PAGES = [
    ("overview", "Security Overview", "layout-dashboard"),
    ("monitor", "Camera & Network Monitor", "radar"),
    ("collection", "Traffic Collection Studio", "download-cloud"),
    ("datasets", "Dataset Management", "database"),
    ("labelling", "Dataset Labelling", "tags"),
    ("schema", "Feature & Schema Studio", "git-branch"),
    ("training", "Model Training", "cpu"),
    ("evaluation", "Model Evaluation", "bar-chart-3"),
    ("detection", "Live AI Detection", "scan-eye"),
    ("securenodes", "Secure Node Ingest", "lock"),
    ("attacklab", "Attack Simulation Lab", "flask-conical"),
    ("honeypot", "Honeypot Monitoring", "bug"),
    ("events", "Security Events & Logs", "list"),
    ("correlation", "Threat Correlation", "network"),
    ("reports", "Reports & Analytics", "file-text"),
    ("settings", "Settings & System Health", "settings"),
]

# ---------------- auth (first-run setup password) ----------------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not get_setting("admin_hash"):
            return redirect(url_for("setup"))
        if not session.get("auth"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "auth required"}), 401
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if get_setting("admin_hash"):
        return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 8:
            return render_template("login.html", setup=True,
                                   error="Password must be at least 8 characters.")
        set_setting("admin_hash", generate_password_hash(pw))
        audit("first_run_setup")
        session["auth"] = True
        return redirect(url_for("page", name="overview"))
    return render_template("login.html", setup=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not get_setting("admin_hash"):
        return redirect(url_for("setup"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if check_password_hash(get_setting("admin_hash"), pw):
            session["auth"] = True
            audit("login")
            return redirect(url_for("page", name="overview"))
        return render_template("login.html", error="Wrong password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

# ---------------- pages ----------------
@app.route("/")
@login_required
def home():
    return redirect(url_for("page", name="overview"))

@app.route("/page/<name>")
@login_required
def page(name):
    valid = {p[0] for p in PAGES}
    if name not in valid:
        abort(404)
    title = dict((p[0], p[1]) for p in PAGES)[name]
    return render_template(f"{name}.html", pages=PAGES, active=name,
                           page_title=title, cfg=config)

# ---------------- API: health / overview ----------------
@app.route("/api/health")
@login_required
def api_health():
    return jsonify({
        "ok": True, "time": time.time(),
        "db": os.path.exists(config.DB_PATH),
        "cowrie": svc.cowrie_status(),
        "system": svc.system_info(),
        "active_model": _active_model_version(),
    })

@app.route("/api/overview")
@login_required
def api_overview():
    with get_db() as con:
        nflows = con.execute("SELECT COUNT(*) c FROM flows").fetchone()["c"]
        nabn = con.execute("SELECT COUNT(*) c FROM predictions WHERE predicted_label=1").fetchone()["c"]
        nsess = con.execute("SELECT COUNT(*) c FROM collection_sessions").fetchone()["c"]
        ncow = con.execute("SELECT COUNT(*) c FROM cowrie_events").fetchone()["c"]
        recent = [dict(r) for r in con.execute(
            "SELECT event_time,event_source,category,severity,source_ip FROM security_events "
            "ORDER BY event_time DESC LIMIT 12").fetchall()]
        ds = con.execute("SELECT COUNT(*) c FROM datasets").fetchone()["c"]
    return jsonify({"ok": True, "flows": nflows, "abnormal": nabn,
                    "sessions": nsess, "cowrie_events": ncow, "datasets": ds,
                    "recent_events": recent, "system": svc.system_info(),
                    "active_model": _active_model_version(),
                    "cowrie": svc.cowrie_status()})

# ---------------- API: datasets ----------------
@app.route("/api/datasets")
@login_required
def api_datasets():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT id,name,source,format,rows,columns,created_at,file_path "
            "FROM datasets ORDER BY created_at DESC").fetchall()]
    return jsonify({"ok": True, "datasets": rows})

@app.route("/api/datasets/upload", methods=["POST"])
@login_required
def api_dataset_upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        return jsonify({"ok": False, "error": "no file"}), 400
    name = secure_filename(f.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"ok": False, "error": f"unsupported type {ext}"}), 400
    dest = os.path.join(config.UPLOAD_DIR, f"{int(time.time())}_{name}")
    f.save(dest)
    size = os.path.getsize(dest)
    try:
        rep = inspect_file(dest)
    except Exception as e:
        return jsonify({"ok": False, "error": f"inspect failed: {e}"}), 500
    checksum = rep.get("checksum_md5", "")
    with get_db() as con:
        cur = con.execute(
            "INSERT INTO datasets(name,source,file_path,format,rows,columns,"
            "schema_version,created_at,checksum,inspect_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (name, "upload", dest, rep["format"], rep["rows_inspected"],
             rep["columns"], "v1", time.time(), checksum, json.dumps(rep)))
        did = cur.lastrowid
        for c in rep["column_detail"]:
            sel = 1 if c["name"] in config.CANONICAL_FEATURES else 0
            con.execute("INSERT INTO dataset_columns(dataset_id,column_name,"
                        "inferred_type,missing_count,unique_count,selected_for_model)"
                        " VALUES(?,?,?,?,?,?)",
                        (did, c["name"], c["dtype"], c["missing"], c["unique"], sel))
    audit("dataset_upload", "dataset", did, {"name": name, "size": size})
    return jsonify({"ok": True, "dataset_id": did, "report": rep})

@app.route("/api/datasets/<int:did>/inspect")
@login_required
def api_dataset_inspect(did):
    with get_db() as con:
        r = con.execute("SELECT inspect_json FROM datasets WHERE id=?", (did,)).fetchone()
    if not r:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "report": json.loads(r["inspect_json"])})

@app.route("/api/datasets/<int:did>/delete", methods=["POST"])
@login_required
def api_dataset_delete(did):
    with get_db() as con:
        r = con.execute("SELECT file_path FROM datasets WHERE id=?", (did,)).fetchone()
        if r and r["file_path"] and os.path.exists(r["file_path"]):
            try: os.remove(r["file_path"])
            except OSError: pass
        con.execute("DELETE FROM dataset_columns WHERE dataset_id=?", (did,))
        con.execute("DELETE FROM datasets WHERE id=?", (did,))
    audit("dataset_delete", "dataset", did)
    return jsonify({"ok": True})

@app.route("/api/datasets/from_collected", methods=["POST"])
@login_required
def api_dataset_from_collected():
    """Build a trainable dataset directly from collected & labelled flows.
    Collect normal sessions, collect abnormal sessions, then call this -> one CSV,
    registered as a dataset, ready to train. No export/re-upload step needed."""
    import pandas as pd
    with get_db() as con:
        rows = con.execute(
            "SELECT f.features_json, f.label, f.timestamp, f.session_id, "
            "s.scenario FROM flows f LEFT JOIN collection_sessions s "
            "ON f.session_id=s.id WHERE f.label IS NOT NULL").fetchall()
    if not rows:
        return jsonify({"ok": False, "error": "no labelled flows collected yet"}), 400
    recs = []
    for r in rows:
        d = json.loads(r["features_json"])
        d["attack"] = r["label"]
        d["type_of_attack"] = "abnormal" if r["label"] == 1 else "normal"
        d["ts"] = r["timestamp"]
        d["uid"] = f"s{r['session_id']}_{len(recs)}"
        d["log_type"] = "conn"
        recs.append(d)
    df = pd.DataFrame(recs)
    counts = df["attack"].value_counts().to_dict()
    name = f"collected_{int(time.time())}.csv"
    dest = os.path.join(config.UPLOAD_DIR, name)
    df.to_csv(dest, index=False)
    rep = inspect_file(dest)
    with get_db() as con:
        cur = con.execute(
            "INSERT INTO datasets(name,source,file_path,format,rows,columns,"
            "schema_version,created_at,checksum,inspect_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (name, "collected", dest, "csv", len(df), df.shape[1], "v1",
             time.time(), rep.get("checksum_md5", ""), json.dumps(rep)))
        did = cur.lastrowid
        for c in rep["column_detail"]:
            sel = 1 if c["name"] in config.CANONICAL_FEATURES else 0
            con.execute("INSERT INTO dataset_columns(dataset_id,column_name,"
                        "inferred_type,missing_count,unique_count,selected_for_model)"
                        " VALUES(?,?,?,?,?,?)",
                        (did, c["name"], c["dtype"], c["missing"], c["unique"], sel))
    audit("dataset_from_collected", "dataset", did, {"rows": len(df), "counts": counts})
    normal = int(counts.get(0, 0)); abn = int(counts.get(1, 0))
    warn = None
    if normal == 0 or abn == 0:
        warn = ("Only one class collected so far. Collect at least one Normal session "
                "AND one Abnormal session before training a usable model.")
    return jsonify({"ok": True, "dataset_id": did, "rows": len(df),
                    "normal": normal, "abnormal": abn, "warning": warn})

# ---------------- API: training ----------------
TRAIN_JOBS = {}   # id -> {status, log, result}

def _train_worker(job_id, dataset_id, params):
    job = TRAIN_JOBS[job_id]
    try:
        import pandas as pd
        with get_db() as con:
            r = con.execute("SELECT file_path,format FROM datasets WHERE id=?",
                            (dataset_id,)).fetchone()
        if not r:
            job.update(status="error", log=["dataset not found"]); return
        job["log"].append("Loading dataset (capped rows for Pi memory)...")
        path = r["file_path"]
        rowcap = int(params.get("row_cap", 200000))
        ext = os.path.splitext(path)[1].lower()
        if ext in (".xlsx", ".xls"):
            df = pd.read_excel(path)
        elif ext == ".parquet":
            df = pd.read_parquet(path)
        elif ext == ".json":
            df = pd.read_json(path, lines=True)
        else:
            df = pd.read_csv(path, nrows=rowcap, low_memory=False,
                             encoding_errors="replace")
        if len(df) > rowcap:
            df = df.sample(rowcap, random_state=1).reset_index(drop=True)
        job["log"].append(f"Loaded {len(df):,} rows, {df.shape[1]} cols")
        job["status"] = "training"
        res = ml.train(df, params)
        job["log"].extend(res.get("log", []))
        if not res.get("ok"):
            job.update(status="error", result=res); return
        # register model
        with get_db() as con:
            con.execute(
                "INSERT INTO models(version,model_path,feature_schema,target,"
                "dataset_ids,split_method,metrics_json,threshold,created_at,active)"
                " VALUES(?,?,?,?,?,?,?,?,?,0)",
                (res["version"], res["model_path"], json.dumps(res["features"]),
                 params.get("target", config.TARGET_COLUMN), str(dataset_id),
                 params.get("split_method", "stratified"),
                 json.dumps(res["metrics"]), res["threshold"], time.time()))
        audit("train_model", "model", res["version"], res["metrics"])
        job.update(status="done", result=res)
    except Exception as e:
        job.update(status="error", log=job["log"]+[f"EXCEPTION: {e}"])

@app.route("/api/training/start", methods=["POST"])
@login_required
def api_train_start():
    body = request.get_json(force=True)
    dataset_id = body.get("dataset_id")
    if not dataset_id:
        return jsonify({"ok": False, "error": "dataset_id required"}), 400
    job_id = f"job_{int(time.time()*1000)}"
    TRAIN_JOBS[job_id] = {"status": "queued", "log": [], "result": None}
    threading.Thread(target=_train_worker, args=(job_id, dataset_id, body),
                     daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})

@app.route("/api/training/<job_id>")
@login_required
def api_train_status(job_id):
    job = TRAIN_JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "unknown job"}), 404
    return jsonify({"ok": True, **job})

# ---------------- API: models ----------------
def _active_model_version():
    with get_db() as con:
        r = con.execute("SELECT version FROM models WHERE active=1 "
                        "ORDER BY created_at DESC LIMIT 1").fetchone()
    return r["version"] if r else None

def _load_active_bundle():
    with get_db() as con:
        r = con.execute("SELECT model_path FROM models WHERE active=1 "
                        "ORDER BY created_at DESC LIMIT 1").fetchone()
    if not r: return None
    try: return ml.load_bundle(r["model_path"])
    except Exception: return None

@app.route("/api/models")
@login_required
def api_models():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT id,version,target,split_method,metrics_json,threshold,"
            "created_at,active FROM models ORDER BY created_at DESC").fetchall()]
    for r in rows:
        r["metrics"] = json.loads(r["metrics_json"]); r.pop("metrics_json")
    return jsonify({"ok": True, "models": rows, "active": _active_model_version()})

@app.route("/api/models/<int:mid>/activate", methods=["POST"])
@login_required
def api_model_activate(mid):
    with get_db() as con:
        con.execute("UPDATE models SET active=0")
        con.execute("UPDATE models SET active=1 WHERE id=?", (mid,))
    audit("activate_model", "model", mid)
    return jsonify({"ok": True})

# ---------------- API: live detection ----------------
@app.route("/api/detections")
@login_required
def api_detections():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT event_time,flow_ref,model_version,predicted_label,"
            "abnormal_score,threshold FROM predictions ORDER BY event_time DESC "
            "LIMIT 100").fetchall()]
    return jsonify({"ok": True, "detections": rows,
                    "active_model": _active_model_version()})

@app.route("/api/detect/run", methods=["POST"])
@login_required
def api_detect_run():
    """Run inference on provided flow rows OR on recent collected flows."""
    bundle = _load_active_bundle()
    if not bundle:
        return jsonify({"ok": False, "error": "Model not trained/deployed"}), 400
    import pandas as pd
    body = request.get_json(force=True) or {}
    rows = body.get("rows")
    if rows:
        df = pd.DataFrame(rows)
    else:
        with get_db() as con:
            frows = con.execute("SELECT features_json,timestamp FROM flows "
                                "ORDER BY id DESC LIMIT 50").fetchall()
        if not frows:
            return jsonify({"ok": False, "error": "no collected flows to score"}), 400
        df = pd.DataFrame([json.loads(r["features_json"]) for r in frows])
    res = ml.predict_rows(bundle, df)
    if not res.get("ok"):
        return jsonify(res), 400
    ver = _active_model_version()
    now = time.time()
    with get_db() as con:
        if res["multiclass"]:
            for i, lbl in enumerate(res["labels"]):
                pl = 0 if str(lbl).lower() in ("normal", "0") else 1
                con.execute("INSERT INTO predictions(event_time,flow_ref,model_version,"
                            "predicted_label,abnormal_score,threshold) VALUES(?,?,?,?,?,?)",
                            (now, f"row{i}", ver, pl, res["scores"][i], 0))
        else:
            for i, p in enumerate(res["predicted"]):
                con.execute("INSERT INTO predictions(event_time,flow_ref,model_version,"
                            "predicted_label,abnormal_score,threshold) VALUES(?,?,?,?,?,?)",
                            (now, f"row{i}", ver, int(p), res["abnormal_score"][i],
                             res["threshold"]))
                if p == 1:
                    add_security_event(event_source="ids", category="abnormal_flow",
                                       severity="high", model_score=res["abnormal_score"][i],
                                       model_version=ver, evidence_ref=f"row{i}")
    return jsonify({"ok": True, "result": res})

# ---------------- API: collection ----------------
@app.route("/api/monitor/visibility")
@login_required
def api_visibility():
    iface = request.args.get("interface") or config.CAPTURE_INTERFACE
    return jsonify({"ok": True, **svc.capture_visibility_test(iface)})

@app.route("/api/collections")
@login_required
def api_collections():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM collection_sessions ORDER BY start_time DESC LIMIT 100").fetchall()]
    return jsonify({"ok": True, "sessions": rows})

@app.route("/api/collections/start", methods=["POST"])
@login_required
def api_collect_start():
    b = request.get_json(force=True)
    dur = min(int(b.get("duration", 60)), config.MAX_CAPTURE_SECONDS)
    with get_db() as con:
        cur = con.execute(
            "INSERT INTO collection_sessions(device_id,interface,scenario,label,"
            "label_source,start_time,status,notes) VALUES(?,?,?,?,?,?,?,?)",
            (b.get("device", "pi-camera"), b.get("interface", config.CAPTURE_INTERFACE),
             b.get("scenario", "camera_idle"), b.get("label", "Unlabelled"),
             b.get("label_source", "manual"), time.time(), "running", b.get("notes", "")))
        sid = cur.lastrowid
    svc.start_capture(sid, b.get("interface", config.CAPTURE_INTERFACE), dur,
                      b.get("label", "Unlabelled"))
    audit("collect_start", "session", sid, b)
    return jsonify({"ok": True, "session_id": sid, "duration": dur})

@app.route("/api/collections/<int:sid>/stop", methods=["POST"])
@login_required
def api_collect_stop(sid):
    n = svc.stop_capture(sid)
    with get_db() as con:
        con.execute("UPDATE collection_sessions SET status='done',end_time=?,"
                    "flow_count=? WHERE id=?", (time.time(), n, sid))
    audit("collect_stop", "session", sid, {"flows": n})
    return jsonify({"ok": True, "flows": n})

@app.route("/api/collections/<int:sid>/export")
@login_required
def api_collect_export(sid):
    import pandas as pd
    with get_db() as con:
        rows = con.execute("SELECT features_json,label,timestamp FROM flows "
                           "WHERE session_id=?", (sid,)).fetchall()
    if not rows:
        return jsonify({"ok": False, "error": "no flows"}), 404
    recs = []
    for r in rows:
        d = json.loads(r["features_json"]); d["attack"] = r["label"]; d["ts"] = r["timestamp"]
        recs.append(d)
    out = os.path.join(config.COLLECT_DIR, f"session_{sid}.csv")
    pd.DataFrame(recs).to_csv(out, index=False)
    return send_file(out, as_attachment=True)

# ---------------- API: labelling ----------------
@app.route("/api/labels", methods=["POST"])
@login_required
def api_labels():
    b = request.get_json(force=True)
    sid = b.get("session_id"); label = b.get("label"); lsrc = b.get("label_source", "analyst_review")
    lv = 1 if str(label).lower() in ("abnormal", "1", "attack") else 0
    with get_db() as con:
        con.execute("UPDATE collection_sessions SET label=?,label_source=? WHERE id=?",
                    (label, lsrc, sid))
        con.execute("UPDATE flows SET label=? WHERE session_id=?", (lv, sid))
    audit("relabel", "session", sid, {"label": label, "source": lsrc})
    return jsonify({"ok": True})

# ---------------- API: schema ----------------
@app.route("/api/schema")
@login_required
def api_schema():
    return jsonify({"ok": True,
                    "canonical": config.CANONICAL_FEATURES,
                    "numeric": config.NUMERIC_FEATURES,
                    "categorical": config.CATEGORICAL_FEATURES,
                    "target": config.TARGET_COLUMN,
                    "multiclass": config.MULTICLASS_COLUMN,
                    "leakage": config.LEAKAGE_FIELDS})

# ---------------- API: attack simulation lab (SAFE/BOUNDED) ----------------
@app.route("/api/simulations/start", methods=["POST"])
@login_required
def api_sim_start():
    b = request.get_json(force=True)
    target = (b.get("target") or "").strip()
    scenario = b.get("scenario", "")
    if not b.get("authorized"):
        return jsonify({"ok": False, "error": "authorised-target confirmation required"}), 400
    ok, why = svc.validate_lab_target(target)
    if not ok:
        return jsonify({"ok": False, "error": why}), 400
    dur = min(int(b.get("duration", 10)), config.SIM_MAX_DURATION)
    rate = min(int(b.get("rate", 5)), config.SIM_MAX_RATE)
    with get_db() as con:
        cur = con.execute(
            "INSERT INTO simulation_runs(scenario,target,start_time,parameters_json,"
            "status,safety_confirmation) VALUES(?,?,?,?,?,1)",
            (scenario, target, time.time(),
             json.dumps({"duration": dur, "rate": rate}), "running"))
        rid = cur.lastrowid
    svc.start_simulation(rid, scenario, target, dur, rate)
    audit("sim_start", "simulation", rid, {"scenario": scenario, "target": target,
                                           "duration": dur, "rate": rate})
    return jsonify({"ok": True, "run_id": rid, "duration": dur, "rate": rate})

@app.route("/api/simulations/<int:rid>/stop", methods=["POST"])
@login_required
def api_sim_stop(rid):
    n = svc.stop_simulation(rid)
    with get_db() as con:
        con.execute("UPDATE simulation_runs SET status='stopped',end_time=?,"
                    "event_count=? WHERE id=?", (time.time(), n, rid))
    audit("sim_stop", "simulation", rid)
    return jsonify({"ok": True, "events": n})

@app.route("/api/simulations")
@login_required
def api_sims():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM simulation_runs ORDER BY start_time DESC LIMIT 50").fetchall()]
    return jsonify({"ok": True, "runs": rows,
                    "allowlist": config.LAB_TARGET_ALLOWLIST,
                    "max_duration": config.SIM_MAX_DURATION,
                    "max_rate": config.SIM_MAX_RATE})

# ---------------- API: honeypot (Cowrie) ----------------
@app.route("/api/honeypot/status")
@login_required
def api_cowrie_status():
    return jsonify({"ok": True, **svc.cowrie_status()})

@app.route("/api/honeypot/ingest", methods=["POST"])
@login_required
def api_cowrie_ingest():
    n = svc.cowrie_ingest()
    return jsonify({"ok": True, "ingested": n})

@app.route("/api/honeypot/events")
@login_required
def api_cowrie_events():
    svc.cowrie_ingest()
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT event_time,eventid,session,src_ip,protocol,parsed_summary "
            "FROM cowrie_events ORDER BY event_time DESC LIMIT 200").fetchall()]
        tops = [dict(r) for r in con.execute(
            "SELECT src_ip, COUNT(*) c FROM cowrie_events GROUP BY src_ip "
            "ORDER BY c DESC LIMIT 10").fetchall()]
    return jsonify({"ok": True, "events": rows, "top_sources": tops})

# ---------------- API: security events + correlation ----------------
@app.route("/api/security-events")
@login_required
def api_sec_events():
    src = request.args.get("source"); sev = request.args.get("severity")
    q = "SELECT * FROM security_events WHERE 1=1"; args = []
    if src: q += " AND event_source=?"; args.append(src)
    if sev: q += " AND severity=?"; args.append(sev)
    q += " ORDER BY event_time DESC LIMIT 300"
    with get_db() as con:
        rows = [dict(r) for r in con.execute(q, args).fetchall()]
    return jsonify({"ok": True, "events": rows})

@app.route("/api/security-events/<int:eid>/ack", methods=["POST"])
@login_required
def api_ack(eid):
    with get_db() as con:
        con.execute("UPDATE security_events SET acknowledged=1 WHERE id=?", (eid,))
    return jsonify({"ok": True})

@app.route("/api/correlation")
@login_required
def api_correlation():
    window = int(request.args.get("window", 300))
    svc.cowrie_ingest()
    with get_db() as con:
        ids = [dict(r) for r in con.execute(
            "SELECT event_time,source_ip,category,severity,evidence_ref "
            "FROM security_events WHERE event_source='ids' ORDER BY event_time DESC "
            "LIMIT 500").fetchall()]
        cow = [dict(r) for r in con.execute(
            "SELECT event_time,src_ip,eventid,parsed_summary FROM cowrie_events "
            "ORDER BY event_time DESC LIMIT 500").fetchall()]
    matched = []
    for i in ids:
        for c in cow:
            if i.get("source_ip") and i["source_ip"] == c["src_ip"] \
               and abs(i["event_time"] - c["event_time"]) <= window:
                matched.append({"ip": i["source_ip"],
                                "ids": i, "cowrie": c,
                                "dt": round(abs(i["event_time"]-c["event_time"]), 1)})
    return jsonify({"ok": True, "window": window, "matched": matched,
                    "ids_count": len(ids), "cowrie_count": len(cow),
                    "note": "IP+time match is correlation, not proof of same attacker (NAT/shared IPs)."})

# ---------------- API: reports ----------------
@app.route("/api/reports/export")
@login_required
def api_report_export():
    kind = request.args.get("kind", "events")
    import pandas as pd
    with get_db() as con:
        if kind == "events":
            df = pd.read_sql_query("SELECT * FROM security_events", con)
        elif kind == "cowrie":
            df = pd.read_sql_query("SELECT * FROM cowrie_events", con)
        elif kind == "models":
            df = pd.read_sql_query("SELECT version,target,metrics_json,threshold,created_at FROM models", con)
        else:
            df = pd.read_sql_query("SELECT * FROM collection_sessions", con)
    out = os.path.join(config.REPORT_DIR, f"report_{kind}_{int(time.time())}.csv")
    df.to_csv(out, index=False)
    return send_file(out, as_attachment=True)

# ---------------- API: secure node ingest (encryption + auth) ----------------
@app.route("/api/nodes")
@login_required
def api_nodes():
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT id,node_id,description,created_at,last_seen,status,payload_count "
            "FROM nodes ORDER BY created_at DESC").fetchall()]
    return jsonify({"ok": True, "nodes": rows, "https": config.ENABLE_HTTPS})

@app.route("/api/nodes/register", methods=["POST"])
@login_required
def api_node_register():
    b = request.get_json(force=True)
    node_id = (b.get("node_id") or "").strip()
    if not node_id:
        return jsonify({"ok": False, "error": "node_id required"}), 400
    key = cnode.new_master_key()
    try:
        with get_db() as con:
            con.execute("INSERT INTO nodes(node_id,master_key,description,created_at,"
                        "status) VALUES(?,?,?,?,'active')",
                        (node_id, key, b.get("description", ""), time.time()))
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "node_id already exists"}), 400
    audit("node_register", "node", node_id)
    # key shown ONCE for provisioning the node; not returned again
    return jsonify({"ok": True, "node_id": node_id, "master_key": key,
                    "note": "Copy this key into the node now — it is shown only once."})

@app.route("/api/nodes/<node_id>/revoke", methods=["POST"])
@login_required
def api_node_revoke(node_id):
    with get_db() as con:
        con.execute("UPDATE nodes SET status='revoked' WHERE node_id=?", (node_id,))
    audit("node_revoke", "node", node_id)
    return jsonify({"ok": True})

@app.route("/api/nodes/<node_id>/payloads")
@login_required
def api_node_payloads(node_id):
    with get_db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT event_time,category,decrypted_summary,src_ip FROM node_payloads "
            "WHERE node_id=? ORDER BY event_time DESC LIMIT 100", (node_id,)).fetchall()]
    return jsonify({"ok": True, "payloads": rows})

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Node-facing endpoint. NOT session-authenticated — authenticated by the node's
    time-bound single-use HMAC token, then AES-256-GCM decrypted. This is how camera/
    laptop nodes securely push encrypted alerts to the server."""
    raw = request.get_data()
    if len(raw) > config.INGEST_MAX_BYTES:
        return jsonify({"ok": False, "error": "payload too large"}), 413
    try:
        b = json.loads(raw.decode("utf-8"))
    except Exception:
        return jsonify({"ok": False, "error": "bad json"}), 400
    node_id = b.get("node_id", "")
    with get_db() as con:
        r = con.execute("SELECT master_key,status FROM nodes WHERE node_id=?",
                        (node_id,)).fetchone()
    if not r:
        return jsonify({"ok": False, "error": "unknown node"}), 401
    if r["status"] != "active":
        return jsonify({"ok": False, "error": "node revoked"}), 403
    master = r["master_key"]
    ok, why = cnode.verify_token(node_id, master, b.get("ts"), b.get("nonce"), b.get("token"))
    if not ok:
        add_security_event(event_source="ingest", category="auth_failure",
                           severity="high", source_ip=request.remote_addr,
                           evidence_ref=node_id)
        return jsonify({"ok": False, "error": why}), 401
    try:
        pt = cnode.decrypt_payload(node_id, master, b.get("aes_nonce"), b.get("ciphertext"))
    except Exception:
        add_security_event(event_source="ingest", category="decrypt_failure",
                           severity="high", source_ip=request.remote_addr,
                           evidence_ref=node_id)
        return jsonify({"ok": False, "error": "decryption/authentication failed"}), 400
    try:
        data = json.loads(pt.decode("utf-8"))
        summary = data.get("event") or data.get("summary") or pt.decode("utf-8")[:200]
        category = data.get("category", data.get("event", "node_alert"))
    except Exception:
        summary = pt.decode("utf-8", "replace")[:200]; category = "node_alert"; data = {}
    now = time.time()
    with get_db() as con:
        con.execute("INSERT INTO node_payloads(node_id,event_time,category,"
                    "decrypted_summary,src_ip) VALUES(?,?,?,?,?)",
                    (node_id, now, category, summary, request.remote_addr))
        con.execute("UPDATE nodes SET last_seen=?,payload_count=payload_count+1 "
                    "WHERE node_id=?", (now, node_id))
        con.execute("INSERT INTO security_events(event_time,event_source,category,"
                    "severity,source_ip,session_id) VALUES(?,?,?,?,?,?)",
                    (now, "node", category, data.get("severity", "medium"),
                     request.remote_addr, node_id))
    return jsonify({"ok": True, "received": True})

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "POST":
        b = request.get_json(force=True)
        for k, v in b.items():
            set_setting(k, v)
        audit("settings_update", details=b)
        return jsonify({"ok": True})
    keys = ["threshold", "capture_interface", "retention_days"]
    return jsonify({"ok": True, "settings": {k: get_setting(k) for k in keys},
                    "system": svc.system_info(), "cowrie": svc.cowrie_status(),
                    "lab_allowlist": config.LAB_TARGET_ALLOWLIST})

@app.errorhandler(404)
def nf(e): return render_template("login.html", error="Page not found"), 404

def startup():
    db.init_db()
    log.info("Camera Sentinel starting")
    ip = svc.lan_ip()
    print("="*60)
    print("  CAMERA SENTINEL")
    print(f"  Dashboard : http://{config.MDNS_HOSTNAME}:{config.PORT}  (if mDNS works)")
    print(f"  LAN access: http://{ip}:{config.PORT}")
    print(f"  Local     : http://127.0.0.1:{config.PORT}")
    print("  First run : open the URL and set an admin password.")
    print("="*60)

if __name__ == "__main__":
    startup()
    ssl_ctx = None
    if config.ENABLE_HTTPS:
        if os.path.exists(config.TLS_CERT) and os.path.exists(config.TLS_KEY):
            ssl_ctx = (config.TLS_CERT, config.TLS_KEY)
            print(f"  TLS       : HTTPS enabled (self-signed). Use https://{svc.lan_ip()}:{config.PORT}")
            print("  Note      : browsers warn on self-signed certs — accept to proceed.")
        else:
            print("  TLS       : CS_HTTPS=1 but cert/key missing. Run: python scripts/gen_cert.py")
            print("              Falling back to HTTP.")
    print("="*60)
    app.run(host=config.HOST, port=config.PORT, threaded=True, ssl_context=ssl_ctx)
