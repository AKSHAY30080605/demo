"""
Model Families & Two-Stage NIDS Architecture.

Contains:
1. Model Family A: Gradient-Boosted Trees (XGBoost) - Fast, high-accuracy tabular flow baseline.
2. Model Family B: Random Forest - Interpretable ensemble with out-of-bag robustness.
3. Model Family C: Feedforward Neural Network (FlowMLP) - Deep learning baseline with feature scaling.
4. TwoStageNIDS: Hierarchical orchestrator combining Stage 1 (Binary) and Stage 2 (Multiclass).
5. Hyperparameter tuning & Cross-Validation helpers.
"""

import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional, Union
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
import xgboost as xgb


def build_xgboost_classifier(
    task: str = "binary",
    n_estimators: int = 120,
    max_depth: int = 6,
    learning_rate: float = 0.1,
    random_state: int = 42
) -> xgb.XGBClassifier:
    """Instantiate XGBoost Classifier optimized for network flow tabular data."""
    if task == "binary":
        objective = "binary:logistic"
        eval_metric = "logloss"
    else:
        objective = "multi:softprob"
        eval_metric = "mlogloss"

    return xgb.XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        tree_method="hist",  # High-speed histogram-based binning
        subsample=0.85,
        colsample_bytree=0.85,
        objective=objective,
        eval_metric=eval_metric,
        random_state=random_state,
        n_jobs=-1
    )


def build_random_forest_classifier(
    task: str = "binary",
    n_estimators: int = 100,
    max_depth: int = 18,
    random_state: int = 42
) -> RandomForestClassifier:
    """Instantiate Random Forest Classifier with balanced class weights."""
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        min_samples_split=4,
        random_state=random_state,
        n_jobs=-1
    )


class NeuralNetFlowClassifier(BaseEstimator, ClassifierMixin):
    """
    Feedforward Neural Network (FlowMLP) tailored for flow metrics.
    Features automated StandardScaler pipeline, ReLU activations,
    L2 regularization (alpha=1e-4), and Adam optimizer with early stopping.
    """
    def __init__(
        self,
        hidden_layer_sizes: Tuple[int, ...] = (128, 64),
        max_iter: int = 50,
        learning_rate_init: float = 0.003,
        random_state: int = 42
    ):
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.learning_rate_init = learning_rate_init
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.mlp = MLPClassifier(
            hidden_layer_sizes=self.hidden_layer_sizes,
            activation="relu",
            solver="adam",
            alpha=1e-4,
            batch_size=256,
            learning_rate="adaptive",
            learning_rate_init=self.learning_rate_init,
            max_iter=self.max_iter,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=5,
            random_state=self.random_state
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        X_scaled = self.scaler.fit_transform(X)
        self.mlp.fit(X_scaled, y)
        self.classes_ = self.mlp.classes_
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        return self.mlp.predict(X_scaled)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        return self.mlp.predict_proba(X_scaled)


class TwoStageNIDS:
    """
    Hierarchical Two-Stage Network Intrusion Detection System:
    ----------------------------------------------------------
    Stage 1: High-throughput Binary Classifier (BENIGN vs ATTACK).
             Serves as first line of defense with minimal false negatives.
    Stage 2: Fine-grained Multiclass Classifier.
             Engaged ONLY when Stage 1 flags an anomaly, classifying the exact
             attack type (DDoS, Hulk, PortScan, Patator, Slowloris, Heartbleed, etc.).
    """
    def __init__(
        self,
        model_family: str = "xgboost",
        random_state: int = 42
    ):
        self.model_family = model_family.lower()
        self.random_state = random_state
        self.stage1_model = None
        self.stage2_model = None
        self.stage2_encoder = LabelEncoder()
        self.train_time_sec: float = 0.0
        self._init_models()

    def _init_models(self):
        if self.model_family == "xgboost":
            self.stage1_model = build_xgboost_classifier(task="binary", random_state=self.random_state)
            self.stage2_model = build_xgboost_classifier(task="multiclass", random_state=self.random_state)
        elif self.model_family == "random_forest":
            self.stage1_model = build_random_forest_classifier(task="binary", random_state=self.random_state)
            self.stage2_model = build_random_forest_classifier(task="multiclass", random_state=self.random_state)
        elif self.model_family in ["neural_network", "mlp"]:
            self.stage1_model = NeuralNetFlowClassifier(random_state=self.random_state)
            self.stage2_model = NeuralNetFlowClassifier(random_state=self.random_state)
        else:
            raise ValueError(f"Unknown model family: {self.model_family}")

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train_raw: pd.Series,
        X_train_attacks: Optional[pd.DataFrame] = None,
        y_train_attacks: Optional[pd.Series] = None
    ):
        """Fit both Stage 1 and Stage 2 models, recording training duration."""
        start_time = time.time()
        print(f"\n[Training] Training TwoStageNIDS ({self.model_family.upper()})...")

        # Stage 1: Binary Training (0 = BENIGN, 1 = ATTACK)
        y_train_binary = (y_train_raw != "BENIGN").astype(int)
        print(f"  Stage 1 (Binary): Training on {len(X_train):,} total flows...")
        self.stage1_model.fit(X_train, y_train_binary)

        # Stage 2: Multiclass Attack Training
        if X_train_attacks is None or y_train_attacks is None:
            mask = (y_train_raw != "BENIGN")
            X_train_attacks = X_train.loc[mask]
            y_train_attacks = y_train_raw.loc[mask]

        print(f"  Stage 2 (Multiclass): Training on {len(X_train_attacks):,} malicious flows across {y_train_attacks.nunique()} attack classes...")
        y_train_encoded = self.stage2_encoder.fit_transform(y_train_attacks)
        self.stage2_model.fit(X_train_attacks, y_train_encoded)

        self.train_time_sec = time.time() - start_time
        print(f"  TwoStageNIDS ({self.model_family.upper()}) training completed in {self.train_time_sec:.2f} seconds.")
        return self

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Hierarchical inference:
        Returns:
            final_predictions (Array of string class labels)
            stage1_binary_preds (0 for BENIGN, 1 for ATTACK)
            stage1_attack_probs (Confidence that flow is an attack)
        """
        n_samples = len(X)
        final_preds = np.array(["BENIGN"] * n_samples, dtype=object)

        # Stage 1: Predict binary status and attack probability
        s1_probs = self.stage1_model.predict_proba(X)
        # Class 1 probability is attack confidence
        s1_attack_prob = s1_probs[:, 1] if s1_probs.shape[1] > 1 else s1_probs[:, 0]
        s1_binary_pred = (s1_attack_prob >= 0.5).astype(int)

        attack_indices = np.where(s1_binary_pred == 1)[0]

        # Stage 2: Fine-grained classification for flagged attacks
        if len(attack_indices) > 0:
            X_flagged = X.iloc[attack_indices]
            s2_encoded_preds = self.stage2_model.predict(X_flagged)
            s2_str_preds = self.stage2_encoder.inverse_transform(s2_encoded_preds)
            final_preds[attack_indices] = s2_str_preds

        return final_preds, s1_binary_pred, s1_attack_prob


def run_stratified_kfold_cv(
    model, X: pd.DataFrame, y: pd.Series, n_splits: int = 5, random_state: int = 42
) -> Tuple[float, float]:
    """Run Stratified K-Fold cross validation and report mean & std of macro F1."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    scores = cross_val_score(model, X, y, cv=skf, scoring="f1_macro", n_jobs=-1)
    return float(np.mean(scores)), float(np.std(scores))
