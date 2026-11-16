"""XGBoost training/evaluation/inference pipeline with a saved, reusable
preprocessing bundle. No data leakage: pipeline is fit on TRAIN only and
reused for val/test/live. Supports binary (attack 0/1) and optional multiclass.
"""
import os, json, time, pickle
import numpy as np, pandas as pd
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score, average_precision_score, accuracy_score)
import config

try:
    import xgboost as xgb
    HAS_XGB = True
except Exception:
    HAS_XGB = False


def _coerce(df, numeric, categorical):
    for c in numeric:
        df[c] = pd.to_numeric(df.get(c), errors="coerce")
    for c in categorical:
        df[c] = df.get(c).astype("object") if c in df else np.nan
    return df


def build_matrix(df, features, numeric, categorical, fit=True, bundle=None):
    """Return X (np array), and the fitted preprocessing bundle."""
    df = _coerce(df.copy(), numeric, categorical)
    num = [c for c in numeric if c in features]
    cat = [c for c in categorical if c in features]
    if fit:
        scaler = StandardScaler()
        Xn = scaler.fit_transform(df[num].fillna(0.0)) if num else np.empty((len(df), 0))
        enc = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        cat_fill = df[cat].astype(str).fillna("NA") if cat else pd.DataFrame(index=df.index)
        Xc = enc.fit_transform(cat_fill) if cat else np.empty((len(df), 0))
        bundle = {"num": num, "cat": cat, "scaler": scaler, "encoder": enc,
                  "features": features}
    else:
        scaler, enc = bundle["scaler"], bundle["encoder"]
        num, cat = bundle["num"], bundle["cat"]
        Xn = scaler.transform(df[num].fillna(0.0)) if num else np.empty((len(df), 0))
        cat_fill = df[cat].astype(str).fillna("NA") if cat else pd.DataFrame(index=df.index)
        Xc = enc.transform(cat_fill) if cat else np.empty((len(df), 0))
    X = np.hstack([Xn, Xc])
    return X, bundle


def _split(df, y, method, groups=None, test_size=0.2, seed=42):
    idx = np.arange(len(df))
    if method == "group" and groups is not None and pd.Series(groups).nunique() > 1:
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        tr, te = next(gss.split(idx, y, groups))
    elif method == "time" and "ts" in df.columns:
        order = np.argsort(df["ts"].values)
        cut = int(len(order)*(1-test_size))
        tr, te = order[:cut], order[cut:]
    else:
        tr, te = train_test_split(idx, test_size=test_size, random_state=seed,
                                  stratify=y if len(np.unique(y)) > 1 else None)
    return tr, te


def train(df, params):
    """params: target, features, split_method, class_weight(bool),
       n_estimators, max_depth, learning_rate, test_size, multiclass(bool)."""
    if not HAS_XGB:
        return {"ok": False, "error": "xgboost not installed"}
    log = []
    target = params.get("target", config.TARGET_COLUMN)
    features = params.get("features") or config.CANONICAL_FEATURES
    features = [f for f in features if f not in config.LEAKAGE_FIELDS and f != target]
    if target not in df.columns:
        return {"ok": False, "error": f"target '{target}' not in dataset"}

    multiclass = bool(params.get("multiclass"))
    df = df.dropna(subset=[target]).reset_index(drop=True)
    if multiclass:
        y_raw = df[target].astype(str)
        classes = sorted(y_raw.unique())
        cmap = {c: i for i, c in enumerate(classes)}
        y = y_raw.map(cmap).values
    else:
        y = pd.to_numeric(df[target], errors="coerce").fillna(0).astype(int).values
        classes = sorted(np.unique(y).tolist())

    if len(np.unique(y)) < 2:
        log.append("WARNING: only one class present — model cannot discriminate. "
                   "Collect/label both normal and abnormal flows.")
        return {"ok": False, "error": "single_class", "log": log, "classes": classes}

    numeric = [c for c in config.NUMERIC_FEATURES if c in features]
    categorical = [c for c in config.CATEGORICAL_FEATURES if c in features]
    features = numeric + categorical
    log.append(f"Using {len(features)} features: {features}")

    groups = df["uid"].values if ("uid" in df and params.get("split_method") == "group") else None
    tr, te = _split(df, y, params.get("split_method", "stratified"), groups,
                    float(params.get("test_size", 0.2)))
    # validation carved from train for threshold selection
    tr2, va = train_test_split(tr, test_size=0.2, random_state=1,
                               stratify=y[tr] if len(np.unique(y[tr])) > 1 else None)

    Xtr, bundle = build_matrix(df.iloc[tr2], features, numeric, categorical, fit=True)
    Xva, _ = build_matrix(df.iloc[va], features, numeric, categorical, fit=False, bundle=bundle)
    Xte, _ = build_matrix(df.iloc[te], features, numeric, categorical, fit=False, bundle=bundle)
    ytr, yva, yte = y[tr2], y[va], y[te]

    spw = 1.0
    if params.get("class_weight") and not multiclass:
        pos = max((ytr == 1).sum(), 1); neg = max((ytr == 0).sum(), 1)
        spw = float(neg/pos); log.append(f"scale_pos_weight={spw:.3f}")

    common = dict(n_estimators=int(params.get("n_estimators", 200)),
                  max_depth=int(params.get("max_depth", 5)),
                  learning_rate=float(params.get("learning_rate", 0.1)),
                  subsample=0.9, colsample_bytree=0.9,
                  n_jobs=int(params.get("n_jobs", 2)), tree_method="hist",
                  eval_metric="mlogloss" if multiclass else "logloss")
    if multiclass:
        clf = xgb.XGBClassifier(objective="multi:softprob",
                                num_class=len(classes), **common)
    else:
        clf = xgb.XGBClassifier(objective="binary:logistic",
                                scale_pos_weight=spw, **common)
    t0 = time.time()
    clf.fit(Xtr, ytr)
    log.append(f"Trained in {time.time()-t0:.2f}s on {len(ytr)} rows")

    # threshold selection on validation (binary only)
    threshold = float(params.get("threshold", config.DEFAULT_THRESHOLD))
    if not multiclass:
        pv = clf.predict_proba(Xva)[:, 1]
        best, bestf1 = threshold, -1
        for t in np.linspace(0.1, 0.9, 17):
            pr, rc, f1, _ = precision_recall_fscore_support(
                yva, (pv >= t).astype(int), average="binary", zero_division=0)
            if f1 > bestf1: bestf1, best = f1, float(t)
        threshold = round(best, 3)
        log.append(f"Selected threshold={threshold} (val F1={bestf1:.3f})")

    # test evaluation
    if multiclass:
        yp = clf.predict(Xte)
        proba = None
    else:
        proba = clf.predict_proba(Xte)[:, 1]
        yp = (proba >= threshold).astype(int)
    cm = confusion_matrix(yte, yp).tolist()
    pr, rc, f1, _ = precision_recall_fscore_support(
        yte, yp, average="binary" if not multiclass else "macro", zero_division=0)
    metrics = {
        "accuracy": round(float(accuracy_score(yte, yp)), 4),
        "precision": round(float(pr), 4), "recall": round(float(rc), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": cm, "classes": classes,
        "test_rows": int(len(yte)), "train_rows": int(len(ytr)),
        "split_method": params.get("split_method", "stratified"),
        "test_class_counts": {str(k): int(v) for k, v in
                              zip(*np.unique(yte, return_counts=True))},
        "multiclass": multiclass,
    }
    if not multiclass and len(np.unique(yte)) > 1:
        try:
            metrics["roc_auc"] = round(float(roc_auc_score(yte, proba)), 4)
            metrics["pr_auc"] = round(float(average_precision_score(yte, proba)), 4)
            tn, fp, fn, tp = confusion_matrix(yte, yp).ravel()
            metrics["false_positive_rate"] = round(float(fp/max(fp+tn, 1)), 4)
        except Exception as e:
            log.append(f"AUC skipped: {e}")
    if len(yte) < 30:
        log.append("WARNING: test set < 30 rows — metrics are not reliable.")

    version = time.strftime("v%Y%m%d_%H%M%S")
    path = os.path.join(config.MODEL_DIR, f"model_{version}.pkl")
    with open(path, "wb") as f:
        pickle.dump({"model": clf, "bundle": bundle, "threshold": threshold,
                     "features": features, "numeric": numeric,
                     "categorical": categorical, "target": target,
                     "multiclass": multiclass, "classes": classes,
                     "class_map": cmap if multiclass else None,
                     "metrics": metrics, "created_at": time.time(),
                     "version": version}, f)
    log.append(f"Saved bundle: {path}")
    return {"ok": True, "version": version, "model_path": path,
            "metrics": metrics, "threshold": threshold, "features": features,
            "log": log}


def load_bundle(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def predict_rows(bundle_obj, df):
    """Live inference. Rejects rows missing required features (no invented values)."""
    feats = bundle_obj["features"]
    missing = [c for c in feats if c not in df.columns]
    if missing:
        return {"ok": False, "error": f"missing required features: {missing}"}
    X, _ = build_matrix(df, feats, bundle_obj["numeric"],
                        bundle_obj["categorical"], fit=False,
                        bundle=bundle_obj["bundle"])
    clf = bundle_obj["model"]
    if bundle_obj["multiclass"]:
        proba = clf.predict_proba(X)
        idx = proba.argmax(1)
        inv = {v: k for k, v in bundle_obj["class_map"].items()}
        labels = [inv[i] for i in idx]
        return {"ok": True, "labels": labels,
                "scores": proba.max(1).round(4).tolist(),
                "multiclass": True}
    proba = clf.predict_proba(X)[:, 1]
    thr = bundle_obj["threshold"]
    return {"ok": True, "abnormal_score": proba.round(4).tolist(),
            "predicted": (proba >= thr).astype(int).tolist(),
            "threshold": thr, "multiclass": False}
