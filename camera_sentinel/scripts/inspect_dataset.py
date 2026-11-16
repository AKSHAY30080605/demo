"""Dataset inspector. Chunk-friendly: never loads a huge file fully by default.
Detects format/delimiter, column types, missingness, label candidates,
class distribution, duplicates, constant columns. Produces a JSON report.
Usage: python scripts/inspect_dataset.py <file> [--rows N]
"""
import sys, os, json, time, hashlib, csv
import pandas as pd

MAX_DEFAULT_ROWS = 200_000  # safety cap for inspection on the Pi

def sniff_format(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".parquet", ".pq"): return "parquet", None
    if ext == ".json": return "json", None
    with open(path, "rb") as f:
        head = f.read(65536).decode("utf-8", "replace")
    if ext in (".xlsx", ".xls"): return "excel", None
    try:
        dialect = csv.Sniffer().sniff(head, delimiters=",\t;|")
        delim = dialect.delimiter
    except Exception:
        delim = "\t" if head.count("\t") > head.count(",") else ","
    return "csv", delim

def load(path, nrows=None):
    fmt, delim = sniff_format(path)
    if fmt == "parquet": df = pd.read_parquet(path); 
    elif fmt == "excel": df = pd.read_excel(path, nrows=nrows)
    elif fmt == "json":
        try: df = pd.read_json(path, lines=True, nrows=nrows)
        except Exception: df = pd.read_json(path)
    else:
        df = pd.read_csv(path, sep=delim, nrows=nrows, low_memory=False,
                         encoding_errors="replace")
    if nrows and len(df) > nrows: df = df.head(nrows)
    return df, fmt, delim

def inspect(path, nrows=MAX_DEFAULT_ROWS):
    t0 = time.time()
    df, fmt, delim = load(path, nrows)
    checksum = hashlib.md5(open(path, "rb").read()).hexdigest()
    cols = []
    for c in df.columns:
        s = df[c]
        info = {"name": str(c), "dtype": str(s.dtype),
                "missing": int(s.isna().sum()),
                "missing_pct": round(100*s.isna().mean(), 2),
                "unique": int(s.nunique(dropna=True)),
                "constant": bool(s.nunique(dropna=True) <= 1)}
        if pd.api.types.is_numeric_dtype(s) and s.notna().any():
            info.update(min=float(s.min()), max=float(s.max()),
                        mean=round(float(s.mean()), 4))
        else:
            vc = s.dropna().astype(str).value_counts().head(5)
            info["top"] = {k: int(v) for k, v in vc.items()}
        cols.append(info)
    # label candidates
    label_cands = [c for c in df.columns
                   if str(c).lower() in ("attack", "label", "type_of_attack", "class", "target")]
    class_dist = {}
    for lc in label_cands:
        class_dist[str(lc)] = {str(k): int(v)
                               for k, v in df[lc].value_counts(dropna=False).head(20).items()}
    rec = {}
    if "log_type" in df.columns:
        rec = {str(k): int(v) for k, v in df["log_type"].value_counts().items()}
    report = {
        "file": os.path.basename(path),
        "path": path,
        "size_bytes": os.path.getsize(path),
        "format": fmt, "delimiter": delim,
        "rows_inspected": int(len(df)),
        "row_limit_applied": bool(nrows and len(df) >= nrows),
        "columns": int(df.shape[1]),
        "checksum_md5": checksum,
        "duplicate_rows": int(df.duplicated().sum()),
        "constant_columns": [str(c) for c in df.columns if df[c].nunique(dropna=True) <= 1],
        "label_candidates": [str(c) for c in label_cands],
        "class_distribution": class_dist,
        "record_families": rec,
        "column_detail": cols,
        "preview": df.head(10).fillna("").astype(str).to_dict(orient="records"),
        "inspect_seconds": round(time.time()-t0, 3),
        "inspected_at": time.time(),
    }
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: inspect_dataset.py <file> [--rows N]"); sys.exit(1)
    path = sys.argv[1]
    nrows = MAX_DEFAULT_ROWS
    if "--rows" in sys.argv:
        nrows = int(sys.argv[sys.argv.index("--rows")+1])
    print(json.dumps(inspect(path, nrows), indent=2)[:4000])
