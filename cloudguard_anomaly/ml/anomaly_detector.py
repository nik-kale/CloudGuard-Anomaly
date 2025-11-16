"""
Machine learning-based anomaly detection for CloudGuard-Anomaly.

Uses unsupervised learning to detect behavioral anomalies and unusual
configurations that may not match known patterns.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Tuple, Optional

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from cloudguard_anomaly.core.models import Resource, Environment, Anomaly, Severity

logger = logging.getLogger(__name__)


class MLAnomalyDetector:
    """Machine learning-based anomaly detector using Isolation Forest."""

    def __init__(self, contamination: float = 0.1):
        """
        Initialize ML anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (0.1 = 10%)
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required. Install with: pip install scikit-learn")

        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []

        logger.info("Initialized ML anomaly detector")

    def extract_features(self, resource: Resource) -> np.ndarray:
        """
        Extract numerical features from resource.

        Args:
            resource: Resource to extract features from

        Returns:
            Feature vector
        """
        features = []

        # Resource age (if available)
        if "creation_date" in resource.properties:
            try:
                from dateutil import parser
                creation = parser.parse(resource.properties["creation_date"])
                age_days = (datetime.now(creation.tzinfo) - creation).days
                features.append(age_days)
            except:
                features.append(0)
        else:
            features.append(0)

        # Number of tags
        features.append(len(resource.tags))

        # Binary security features
        props = resource.properties
        features.append(1 if props.get("encrypted") or props.get("encryption") else 0)
        features.append(1 if props.get("publicly_accessible") else 0)
        features.append(1 if props.get("public_ip") or props.get("public_ip_address") else 0)

        # Versioning
        versioning = props.get("versioning", {})
        if isinstance(versioning, dict):
            features.append(1 if versioning.get("enabled") else 0)
        else:
            features.append(0)

        # Network exposure score
        if "ingress" in props:
            ingress_rules = props.get("ingress", [])
            features.append(len(ingress_rules))

            # Count open rules
            open_rules = sum(
                1
                for rule in ingress_rules
                if "0.0.0.0/0" in str(rule.get("cidr_blocks", []))
            )
            features.append(open_rules)
        else:
            features.append(0)
            features.append(0)

        # Backup configuration
        features.append(1 if props.get("backup_retention_period", 0) > 0 else 0)
        features.append(props.get("backup_retention_period", 0))

        # Multi-AZ / HA
        features.append(1 if props.get("multi_az") else 0)

        return np.array(features)

    def train(self, environments: List[Environment]) -> None:
        """
        Train anomaly detector on historical data.

        Args:
            environments: List of environments to train on
        """
        all_features = []

        for env in environments:
            for resource in env.resources:
                try:
                    features = self.extract_features(resource)
                    all_features.append(features)
                except Exception as e:
                    logger.warning(f"Failed to extract features for {resource.id}: {e}")

        if not all_features:
            raise ValueError("No features extracted for training")

        X = np.array(all_features)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True

        logger.info(f"Trained ML model on {len(all_features)} resources")

    def detect_anomalies(
        self, environment: Environment, threshold: float = -0.5
    ) -> List[Tuple[Resource, float]]:
        """
        Detect anomalous resources.

        Args:
            environment: Environment to analyze
            threshold: Anomaly score threshold (lower = more anomalous)

        Returns:
            List of (resource, anomaly_score) tuples
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before detection")

        anomalies = []

        for resource in environment.resources:
            try:
                features = self.extract_features(resource)
                features_scaled = self.scaler.transform([features])

                # Get anomaly prediction and score
                prediction = self.model.predict(features_scaled)[0]
                score = self.model.score_samples(features_scaled)[0]

                # -1 indicates anomaly, score is negative (more negative = more anomalous)
                if prediction == -1 or score < threshold:
                    anomalies.append((resource, abs(score)))

            except Exception as e:
                logger.warning(f"Failed to detect anomaly for {resource.id}: {e}")

        # Sort by anomaly score (highest first)
        anomalies.sort(key=lambda x: x[1], reverse=True)

        logger.info(f"Detected {len(anomalies)} ML-based anomalies")

        return anomalies

    def create_anomaly_objects(
        self, anomalies: List[Tuple[Resource, float]]
    ) -> List[Anomaly]:
        """
        Convert anomaly detections to Anomaly objects.

        Args:
            anomalies: List of (resource, score) tuples

        Returns:
            List of Anomaly objects
        """
        anomaly_objects = []

        for resource, score in anomalies:
            severity = self._score_to_severity(score)

            anomaly = Anomaly(
                id=f"ml-anomaly-{uuid.uuid4()}",
                type="ml_behavioral_anomaly",
                severity=severity,
                resource=resource,
                baseline={},
                current=resource.properties,
                changes=[
                    {
                        "type": "behavioral_anomaly",
                        "anomaly_score": float(score),
                        "detection_method": "isolation_forest",
                        "model_version": "1.0",
                    }
                ],
                impact=f"Resource exhibits unusual behavior patterns "
                f"(anomaly score: {score:.3f}). This may indicate a "
                f"misconfiguration, security issue, or unauthorized change.",
                timestamp=datetime.utcnow(),
            )

            anomaly_objects.append(anomaly)

        return anomaly_objects

    def _score_to_severity(self, score: float) -> Severity:
        """Convert anomaly score to severity level."""
        if score > 0.7:
            return Severity.CRITICAL
        elif score > 0.5:
            return Severity.HIGH
        elif score > 0.3:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def save_model(self, path: str) -> None:
        """
        Save trained model to disk.

        Args:
            path: File path to save model
        """
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "is_trained": self.is_trained,
                "feature_names": self.feature_names,
            },
            path,
        )

        logger.info(f"Saved ML model to {path}")

    def load_model(self, path: str) -> None:
        """
        Load trained model from disk.

        Args:
            path: File path to load model from
        """
        data = joblib.dump(path)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_trained = data["is_trained"]
        self.feature_names = data.get("feature_names", [])

        logger.info(f"Loaded ML model from {path}")

    def get_feature_importance(self) -> Optional[np.ndarray]:
        """Get feature importance scores if available."""
        if not self.is_trained:
            return None

        # Isolation Forest doesn't directly provide feature importance
        # This is a placeholder for more advanced models
        return None
