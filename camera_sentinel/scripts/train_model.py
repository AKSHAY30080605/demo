"""CLI training wrapper. Usage:
  python scripts/train_model.py <dataset.csv> [--target attack] [--rows 150000]
"""
import sys, os, json, argparse
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config, ml_pipeline as ml

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--target", default=config.TARGET_COLUMN)
    ap.add_argument("--rows", type=int, default=150000)
    ap.add_argument("--split", default="stratified", choices=["stratified","group","time"])
    ap.add_argument("--class-weight", action="store_true")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=5)
    ap.add_argument("--multiclass", action="store_true")
    a = ap.parse_args()
    ext = os.path.splitext(a.dataset)[1].lower()
    if ext in (".xlsx",".xls"): df = pd.read_excel(a.dataset)
    else: df = pd.read_csv(a.dataset, nrows=a.rows, low_memory=False, encoding_errors="replace")
    if len(df) > a.rows: df = df.sample(a.rows, random_state=1)
    res = ml.train(df, {"target": a.target, "split_method": a.split,
                        "class_weight": a.class_weight, "n_estimators": a.n_estimators,
                        "max_depth": a.max_depth, "multiclass": a.multiclass})
    print(json.dumps(res.get("metrics", res), indent=2))
    if res.get("ok"): print("\nModel saved:", res["model_path"])

if __name__ == "__main__": main()
