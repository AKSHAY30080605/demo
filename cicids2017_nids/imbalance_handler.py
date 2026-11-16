"""
Class Imbalance Handling and Two-Stage Architecture Data Management.

1. Stratified Train / Val / Test splitting preserving rare class ratios.
2. Adaptive SMOTE / Hybrid Resampling that dynamically adjusts k_neighbors
   for ultra-rare attack classes (e.g. Heartbleed with <15 samples).
3. Two-Stage Partitioning:
   - Stage 1: Binary Detection (BENIGN vs. ANY ATTACK).
   - Stage 2: Multiclass Attack Discrimination (operating only on malicious flows).
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Optional
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE, RandomOverSampler


class ImbalanceHandler:
    """
    Manages data splitting and resampling for highly skewed network intrusion data.
    """
    def __init__(self, test_size: float = 0.15, val_size: float = 0.15, random_state: int = 42):
        self.test_size = test_size
        self.val_size = val_size
        self.random_state = random_state

    def stratified_split(
        self, X: pd.DataFrame, y: pd.Series
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
        """
        Creates a stratified Train, Validation, and Test split, preserving rare attack proportions.
        """
        print(f"[Split] Performing stratified split (Train: {1 - self.test_size - self.val_size:.0%}, Val: {self.val_size:.0%}, Test: {self.test_size:.0%})...")
        
        # Test split
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X, y, test_size=self.test_size, stratify=y, random_state=self.random_state
        )
        
        # Relative validation split
        relative_val_size = self.val_size / (1.0 - self.test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val, y_train_val, test_size=relative_val_size, stratify=y_train_val, random_state=self.random_state
        )
        
        print(f"        Train set: {len(X_train):,} flows | Val set: {len(X_val):,} flows | Test set: {len(X_test):,} flows")
        return X_train, X_val, X_test, y_train, y_val, y_test

    @staticmethod
    def prepare_stage1_binary_labels(y: pd.Series) -> pd.Series:
        """
        Stage 1 Target: 0 for BENIGN, 1 for ATTACK (any attack type).
        """
        return (y != "BENIGN").astype(int)

    @staticmethod
    def prepare_stage2_multiclass_data(
        X: pd.DataFrame, y: pd.Series
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Stage 2 Filter: Retains ONLY malicious flows (removes BENIGN flows)
        to train fine-grained attack triage without benign class dominance.
        """
        attack_mask = (y != "BENIGN")
        X_attacks = X.loc[attack_mask].copy()
        y_attacks = y.loc[attack_mask].copy()
        return X_attacks, y_attacks

    def apply_adaptive_smote(
        self, X: pd.DataFrame, y: pd.Series, target_minority_threshold: int = 500
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Applies an adaptive resampling strategy:
        - For classes with very few samples (n < 6), standard SMOTE fails because k_neighbors=5.
        - We first use RandomOverSampler to bring ultra-rare classes to at least 10 samples,
          then apply SMOTE with dynamic k_neighbors = min(k, class_samples - 1).
        """
        counts = y.value_counts()
        min_count = counts.min()
        
        print(f"[Resampling] Applying adaptive SMOTE (Minimum class size before resampling: {min_count})...")
        
        # Step A: Boost ultra-rare classes (< 8 samples) slightly with RandomOverSampler so SMOTE can construct neighborhoods
        rare_classes = counts[counts < 8].index.tolist()
        if rare_classes:
            sampling_strategy_ros = {cls: max(counts[cls], 10) for cls in rare_classes}
            ros = RandomOverSampler(sampling_strategy=sampling_strategy_ros, random_state=self.random_state)
            X, y = ros.fit_resample(X, y)
            
        # Re-check counts
        updated_counts = pd.Series(y).value_counts()
        new_min = updated_counts.min()
        k_neighbors = max(1, min(5, new_min - 1))
        
        # Construct target sampling strategy: cap majority dominance without exploding memory
        # Increase minority classes up to at least target_minority_threshold or 20% of median class
        median_count = int(updated_counts.median())
        target_size = max(target_minority_threshold, min(median_count, 3000))
        
        sampling_strategy_smote = {}
        for cls, count in updated_counts.items():
            if count < target_size:
                sampling_strategy_smote[cls] = target_size
                
        if sampling_strategy_smote:
            smote = SMOTE(
                sampling_strategy=sampling_strategy_smote,
                k_neighbors=k_neighbors,
                random_state=self.random_state
            )
            X_resampled, y_resampled = smote.fit_resample(X, y)
            print(f"        Resampling complete: Expanded from {len(X):,} to {len(X_resampled):,} flows.")
            return pd.DataFrame(X_resampled, columns=X.columns), pd.Series(y_resampled)
        else:
            return X, y
