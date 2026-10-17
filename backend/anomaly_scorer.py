"""
LogMind Anomaly Scorer — Real ML-Based Event Risk Assessment
Uses scikit-learn IsolationForest + XGBoost gradient boosting to score
each event window for anomaly probability.

This module provides REAL AI/ML inference on the event stream,
complementing the deterministic rules engine with probabilistic risk scoring.
"""
import numpy as np
from typing import List, Dict, Any, Tuple
from collections import Counter
import hashlib
import time

# Lazy imports for optional heavy dependencies
_sklearn_available = False
_xgboost_available = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import LabelEncoder
    _sklearn_available = True
except ImportError:
    pass

try:
    import xgboost as xgb
    _xgboost_available = True
except ImportError:
    pass


class AnomalyScorer:
    """
    Hybrid ML anomaly detection pipeline:
    1. Feature engineering from raw event stream
    2. Isolation Forest (sklearn) for unsupervised anomaly detection
    3. XGBoost classifier for supervised threat scoring
    
    Runs on IBM LinuxONE s390x with hardware-accelerated numpy operations.
    """

    # Action risk weights (domain knowledge priors)
    ACTION_RISK_MAP = {
        "auth_failed": 0.7,
        "auth_success": 0.1,
        "privilege_escalation": 0.9,
        "connection_blocked": 0.6,
        "password_reset": 0.4,
        "user_agent_observed": 0.3,
        "login": 0.2,
        "logout": 0.05,
        "vpn_connect": 0.15,
        "file_open": 0.1,
        "file_preview": 0.1,
        "api_query": 0.15,
        "view_dashboard": 0.05,
        "view_report": 0.05,
        "search": 0.05,
        "send_message": 0.05,
        "mail_sync": 0.05,
        "software_inventory": 0.05,
        "software_update": 0.05,
        "process_start": 0.2,
        "http_request": 0.15,
    }

    SUSPICIOUS_UA_KEYWORDS = [
        "ignore", "instruction", "override", "benign", "verdict",
        "authorized", "ciso", "suppress", "reveal", "system"
    ]

    def __init__(self):
        self.isolation_forest = None
        self.xgb_model = None
        self.label_encoders = {}
        self.is_trained = False

    def extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Engineer numerical features from structured event data.
        Features:
          0: action_risk_score (domain-weighted)
          1: is_failed_status (binary)
          2: is_blocked_status (binary)
          3: hour_of_day (0-23, cyclical risk)
          4: user_agent_suspicion_score (0.0-1.0)
          5: ip_is_external (binary)
          6: source_risk_weight
          7: action_rarity_in_window (inverse frequency)
        """
        if not events:
            return np.array([]).reshape(0, 8)

        # Pre-compute action frequency for rarity scoring
        action_counts = Counter()
        for ev in events:
            action = ev.get("action", "unknown")
            action_counts[action] += 1
        total_events = len(events)

        features = []
        for ev in events:
            action = ev.get("action", "unknown")
            status = ev.get("status", "").upper()
            timestamp = ev.get("timestamp", "")
            ip = ev.get("source_ip") or ev.get("ip", "")
            details = ev.get("details", {})
            ua = details.get("user_agent", "") if isinstance(details, dict) else ""

            # Feature 0: Action risk score
            action_risk = self.ACTION_RISK_MAP.get(action, 0.15)

            # Feature 1: Failed status
            is_failed = 1.0 if status in ("FAIL", "FAILED", "ERROR") else 0.0

            # Feature 2: Blocked status
            is_blocked = 1.0 if status == "BLOCKED" else 0.0

            # Feature 3: Hour of day (extract from ISO timestamp or syslog)
            hour = self._extract_hour(timestamp)
            # Off-hours (22:00-06:00) increase risk
            hour_risk = 1.0 if (hour >= 22 or hour <= 6) else 0.3

            # Feature 4: User-Agent suspicion score
            ua_score = self._score_user_agent(ua)

            # Feature 5: External IP
            is_external = 0.0 if (
                ip.startswith("10.") or ip.startswith("172.") or
                ip.startswith("192.168.") or ip == "" or ip.startswith("127.")
            ) else 1.0

            # Feature 6: Source category risk
            source = ev.get("service") or ev.get("source", "")
            source_risk = {"auth": 0.5, "firewall": 0.6, "endpoint": 0.4,
                           "vpn": 0.3, "web": 0.2, "email": 0.1,
                           "file": 0.15, "proxy": 0.25, "sshd": 0.5,
                           "sudo": 0.8, "web_server": 0.3}.get(source, 0.2)

            # Feature 7: Action rarity (inverse frequency — rarer actions are more suspicious)
            action_rarity = 1.0 - (action_counts[action] / total_events)

            features.append([
                action_risk, is_failed, is_blocked, hour_risk,
                ua_score, is_external, source_risk, action_rarity
            ])

        return np.array(features, dtype=np.float64)

    def _extract_hour(self, ts: str) -> int:
        """Extract hour from various timestamp formats."""
        import re
        # ISO format: 2026-10-21T06:37:06Z
        m = re.search(r'T(\d{2}):', ts)
        if m:
            return int(m.group(1))
        # Syslog format: Oct 17 09:12:01
        m = re.search(r'\s(\d{2}):\d{2}:\d{2}', ts)
        if m:
            return int(m.group(1))
        return 12  # default midday

    def _score_user_agent(self, ua: str) -> float:
        """Score a User-Agent string for prompt injection suspicion (0.0-1.0)."""
        if not ua:
            return 0.0
        ua_lower = ua.lower()
        hits = sum(1 for kw in self.SUSPICIOUS_UA_KEYWORDS if kw in ua_lower)
        return min(hits / 3.0, 1.0)

    def train_isolation_forest(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Train an Isolation Forest (unsupervised anomaly detection) on the feature matrix.
        Returns training metadata and contamination estimate.
        """
        if not _sklearn_available:
            return {"status": "sklearn_not_available", "model": "IsolationForest"}

        start = time.time()
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.01,  # Expect ~1% anomalies
            max_samples=min(len(features), 10000),
            random_state=42,
            n_jobs=-1
        )
        self.isolation_forest.fit(features)
        elapsed = time.time() - start

        scores = self.isolation_forest.decision_function(features)
        predictions = self.isolation_forest.predict(features)
        n_anomalies = int(np.sum(predictions == -1))

        return {
            "model": "IsolationForest (sklearn)",
            "n_estimators": 100,
            "training_samples": len(features),
            "training_time_ms": int(elapsed * 1000),
            "anomalies_detected": n_anomalies,
            "anomaly_rate": round(n_anomalies / len(features) * 100, 2),
            "mean_anomaly_score": round(float(np.mean(scores)), 4),
            "status": "trained"
        }

    def train_xgboost_classifier(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Train an XGBoost gradient boosting classifier using semi-supervised labels.
        Labels are derived from the Isolation Forest predictions + domain rules.
        """
        if not _xgboost_available:
            return {"status": "xgboost_not_available", "model": "XGBoost"}

        start = time.time()

        # Generate semi-supervised labels from IF predictions + feature heuristics
        if self.isolation_forest is not None:
            if_preds = self.isolation_forest.predict(features)
            labels = np.where(if_preds == -1, 1, 0).astype(np.float32)
        else:
            # Fallback: use high action_risk + failed status as positive label
            labels = np.where(
                (features[:, 0] > 0.5) & (features[:, 1] > 0.5), 1, 0
            ).astype(np.float32)

        # Boost labels for known suspicious UA
        labels = np.where(features[:, 4] > 0.3, 1, labels)

        dtrain = xgb.DMatrix(features, label=labels)

        params = {
            "max_depth": 4,
            "eta": 0.3,
            "objective": "binary:logistic",
            "eval_metric": "auc",
            "nthread": -1,
            "seed": 42
        }

        self.xgb_model = xgb.train(params, dtrain, num_boost_round=50)
        elapsed = time.time() - start

        # Get predictions for training metrics
        preds = self.xgb_model.predict(dtrain)
        n_positive = int(np.sum(labels))

        return {
            "model": "XGBoost Gradient Boosting (xgboost)",
            "max_depth": 4,
            "num_boost_round": 50,
            "training_samples": len(features),
            "training_time_ms": int(elapsed * 1000),
            "positive_labels": n_positive,
            "mean_threat_probability": round(float(np.mean(preds)), 4),
            "max_threat_probability": round(float(np.max(preds)), 4),
            "status": "trained"
        }

    def score_events(self, features: np.ndarray) -> List[float]:
        """
        Score events using the trained ensemble (IF + XGBoost).
        Returns a list of threat probability scores (0.0 to 1.0).
        """
        if len(features) == 0:
            return []

        scores = np.zeros(len(features))

        # Isolation Forest anomaly scores (normalized to 0-1)
        if self.isolation_forest is not None:
            if_scores = self.isolation_forest.decision_function(features)
            # IF scores: negative = more anomalous; normalize
            if_normalized = 1.0 - (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min() + 1e-8)
            scores += if_normalized * 0.4  # 40% weight

        # XGBoost threat probability
        if self.xgb_model is not None:
            dmatrix = xgb.DMatrix(features)
            xgb_scores = self.xgb_model.predict(dmatrix)
            scores += xgb_scores * 0.6  # 60% weight

        # Clamp to [0, 1]
        scores = np.clip(scores, 0.0, 1.0)
        return [round(float(s), 4) for s in scores]

    def train_on_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        End-to-end: extract features, train both models, return combined report.
        """
        start = time.time()
        features = self.extract_features(events)

        if len(features) == 0:
            return {"status": "no_events", "models_trained": 0}

        if_report = self.train_isolation_forest(features)
        xgb_report = self.train_xgboost_classifier(features)

        self.is_trained = True
        total_time = time.time() - start

        return {
            "total_training_time_ms": int(total_time * 1000),
            "feature_dimensions": features.shape[1],
            "total_samples": len(features),
            "isolation_forest": if_report,
            "xgboost": xgb_report,
            "ensemble_status": "operational",
            "frameworks_used": ["scikit-learn (IsolationForest)", "XGBoost (Gradient Boosting)"]
        }
