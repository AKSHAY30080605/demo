"""Re-print saved metrics for a model bundle. Usage: evaluate_model.py <model.pkl>"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ml_pipeline as ml
b = ml.load_bundle(sys.argv[1])
print(json.dumps(b["metrics"], indent=2))
