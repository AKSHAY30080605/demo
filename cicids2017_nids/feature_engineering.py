"""
Feature Engineering and Selection Pipeline for CICIDS2017 NIDS.

1. Variance Thresholding: Filters constant and near-zero-variance columns (e.g., bulk rate metrics).
2. Collinear Feature Pruning: Pearson correlation > 0.95 dropped, while strictly protecting
   essential timing, flag, and protocol features critical for distinguishing flood vs. slow-rate attacks.
3. Feature Importance Ranking: Tree-based feature importance ranking (reporting top 15-20 features).
"""

import numpy as np
import pandas as pd
from typing import List, Tuple, Dict
from sklearn.feature_selection import VarianceThreshold
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier


# Critical domain features that must NEVER be dropped by collinearity pruning:
# They contain vital discriminatory signals between volumetric floods (SYN/UDP flood)
# and slow-rate application layer state exhaustion (Slowloris/Slowhttptest).
PROTECTED_DOMAIN_FEATURES = {
    "Destination Port",
    "Flow Duration",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Active Mean",
    "Active Std",
    "Idle Mean",
    "Idle Std",
    "Flow Bytes/s",
    "Flow Packets/s"
}


class CICIDSFeatureSelector:
    """
    Automated feature selector tuned specifically for network flow telemetry.
    """
    def __init__(self, variance_threshold: float = 1e-4, correlation_threshold: float = 0.95):
        self.variance_threshold = variance_threshold
        self.correlation_threshold = correlation_threshold
        self.selected_features_: List[str] = []
        self.dropped_variance_features_: List[str] = []
        self.dropped_collinear_features_: List[Tuple[str, str, float]] = []
        self.feature_importances_: pd.Series = pd.Series(dtype=float)

    def fit_transform(self, X: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
        """Fit selector on training features and return filtered DataFrame."""
        return self.fit(X, y).transform(X)

    def fit(self, X: pd.DataFrame, y: pd.Series):
        """Fit variance threshold, correlation filtering, and importance ranking."""
        print("\n[FeatureSelection] Initiating Feature Selection Pipeline...")
        initial_count = X.shape[1]
        
        # Step 1: Remove Zero/Near-Zero Variance features
        vt = VarianceThreshold(threshold=self.variance_threshold)
        vt.fit(X)
        kept_var_mask = vt.get_support()
        self.dropped_variance_features_ = [col for col, keep in zip(X.columns, kept_var_mask) if not keep]
        X_var = X.loc[:, kept_var_mask]
        
        print(f"  [1/3] Variance Filter: Dropped {len(self.dropped_variance_features_)} low-variance feature(s).")
        if self.dropped_variance_features_:
            print(f"        Dropped: {self.dropped_variance_features_[:6]} ...")

        # Step 2: Collinear Feature Pruning (Correlation > threshold)
        corr_matrix = X_var.corr().abs()
        upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        
        to_drop_collinear = set()
        self.dropped_collinear_features_ = []
        
        for col in upper_tri.columns:
            # Check if this column correlates with any previously checked column above threshold
            high_corr = upper_tri[col][upper_tri[col] > self.correlation_threshold]
            for orig_col, corr_val in high_corr.items():
                # If one of the columns is in protected domain features, keep the protected one!
                if col in PROTECTED_DOMAIN_FEATURES and orig_col not in PROTECTED_DOMAIN_FEATURES:
                    to_drop_collinear.add(orig_col)
                    self.dropped_collinear_features_.append((orig_col, col, corr_val))
                elif orig_col in PROTECTED_DOMAIN_FEATURES and col not in PROTECTED_DOMAIN_FEATURES:
                    to_drop_collinear.add(col)
                    self.dropped_collinear_features_.append((col, orig_col, corr_val))
                elif col not in PROTECTED_DOMAIN_FEATURES and orig_col not in PROTECTED_DOMAIN_FEATURES:
                    to_drop_collinear.add(col)
                    self.dropped_collinear_features_.append((col, orig_col, corr_val))
                else:
                    # Both are protected: keep both!
                    pass

        X_corr = X_var.drop(columns=list(to_drop_collinear), errors='ignore')
        print(f"  [2/3] Collinear Filter (Threshold > {self.correlation_threshold}): Dropped {len(to_drop_collinear)} collinear feature(s).")
        print(f"        Kept protected protocol, flag-ratio, and timing features intact.")

        self.selected_features_ = list(X_corr.columns)
        print(f"        Feature count reduced from {initial_count} to {len(self.selected_features_)}.")

        # Step 3: Tree-Based Feature Importance Ranking
        print("  [3/3] Computing Feature Importance ranking using ExtraTreesClassifier...")
        sample_size = min(len(X_corr), 15000)
        idx_sample = np.random.choice(len(X_corr), size=sample_size, replace=False)
        
        rf = ExtraTreesClassifier(n_estimators=50, max_depth=15, random_state=42, n_jobs=-1)
        rf.fit(X_corr.iloc[idx_sample], y.iloc[idx_sample])
        
        self.feature_importances_ = pd.Series(
            rf.feature_importances_, index=self.selected_features_
        ).sort_values(ascending=False)

        top_20 = self.feature_importances_.head(20)
        print("\n" + "-"*65)
        print("               TOP 20 MOST DISCRIMINATIVE FLOW FEATURES")
        print("-"*65)
        for rank, (feat, score) in enumerate(top_20.items(), 1):
            print(f" {rank:2d}. {feat:<36} Importance: {score:.5f}")
        print("-"*65 + "\n")
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Filter incoming DataFrame to selected features only."""
        if not self.selected_features_:
            raise ValueError("Selector has not been fitted yet.")
        return X[self.selected_features_].copy()
