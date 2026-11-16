"""Prepare a Pi-sized training subset from the full IoT-SFC v2 CSV (12.63 GB).
Chunk-reads the huge file, keeps only canonical + label columns, and builds a
balanced/sampled subset you can actually train on a 4 GB Pi.

Usage:
  python scripts/prepare_dataset.py /path/iot_dataset_v7.csv \
      --out data/collected/iotsfc_subset.csv --per-class 60000 --chunk 200000
"""
import sys, os, argparse, csv
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

KEEP = list(dict.fromkeys(
    config.CANONICAL_FEATURES + [config.TARGET_COLUMN,
    config.MULTICLASS_COLUMN, "log_type", "ts", "uid"]))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default=str(config.COLLECT_DIR / "iotsfc_subset.csv"))
    ap.add_argument("--per-class", type=int, default=60000,
                    help="max rows to keep per attack-value of type_of_attack")
    ap.add_argument("--chunk", type=int, default=200000)
    ap.add_argument("--max-scan", type=int, default=1500000,
                    help="maximum rows to scan before finishing (default 1.5M, 0 for full file)")
    ap.add_argument("--conn-only", action="store_true",
                    help="keep only log_type==conn (flow records)")
    a = ap.parse_args()

    # read header to know which KEEP cols actually exist
    hdr = pd.read_csv(a.csv, nrows=0)
    cols = [c for c in KEEP if c in hdr.columns]
    print("Keeping columns:", cols)
    counts = {}
    buckets = {}
    total = 0
    for i, chunk in enumerate(pd.read_csv(a.csv, usecols=cols, chunksize=a.chunk,
                                          low_memory=False, encoding_errors="replace")):
        if a.conn_only and "log_type" in chunk:
            chunk = chunk[chunk["log_type"] == "conn"]
        keycol = config.MULTICLASS_COLUMN if config.MULTICLASS_COLUMN in chunk else config.TARGET_COLUMN
        for key, grp in chunk.groupby(keycol):
            have = counts.get(key, 0)
            if have >= a.per_class:
                continue
            need = a.per_class - have
            take = grp.sample(min(len(grp), need), random_state=1) if len(grp) > need else grp
            buckets.setdefault(key, []).append(take)
            counts[key] = have + len(take)
        total += len(chunk)
        done = sum(counts.values())
        print(f"chunk {i+1}: scanned {total:,} rows, kept {done:,}", end="\r")
        if a.max_scan and total >= a.max_scan:
            print(f"\nReached max-scan limit of {a.max_scan:,} rows.")
            break
    print()
    frames = [pd.concat(v) for v in buckets.values()]
    out = pd.concat(frames).sample(frac=1, random_state=7).reset_index(drop=True)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out.to_csv(a.out, index=False)
    print(f"\nWROTE {len(out):,} rows -> {a.out}")
    print("Class distribution:")
    kc = config.MULTICLASS_COLUMN if config.MULTICLASS_COLUMN in out else config.TARGET_COLUMN
    print(out[kc].value_counts().to_string())

if __name__ == "__main__":
    main()
