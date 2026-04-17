"""
anomaly_detector.py — Z-score + DBSCAN anomaly detection for Pattern 47.

Feature vector per session (7 dimensions):
  0: attempt_count      (normalised)
  1: session_dur_ms     (log-normalised)
  2: input_max_len      (normalised)
  3: is_http            (0/1)
  4: is_telnet          (0/1)
  5: is_mqtt            (0/1)
  6: cmd_len            (normalised)

A session is flagged as ZERO_DAY_ANOMALY (pattern 47) when:
  a) Its Z-score distance from the running centroid > ZSCORE_THRESHOLD, AND
  b) No Group A-D heuristic matched it (caller's responsibility).

DBSCAN is run periodically over the last N sessions to find structural
outliers (-1 label) — these are also surfaced as pattern 47.
"""
from __future__ import annotations

import math
from collections import deque
from typing import Deque, List, Optional, Tuple

import numpy as np
from scipy.spatial.distance import cdist
from sklearn.preprocessing import StandardScaler  # type: ignore

from patterns import PatternID

try:
    from sklearn.cluster import DBSCAN  # type: ignore
    _DBSCAN_AVAILABLE = True
except ImportError:
    _DBSCAN_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
ZSCORE_THRESHOLD  = 3.5    # standard deviations
HISTORY_SIZE      = 500    # rolling window of sessions for centroid
DBSCAN_EPS        = 1.5    # neighbourhood radius (in std-normalised space)
DBSCAN_MIN_SAMPLES = 5     # min points to form a core point
DBSCAN_BATCH_SIZE = 200    # run DBSCAN every N new sessions


def _session_to_vector(session: dict) -> np.ndarray:
    """Convert a session dict to a 7-element float feature vector."""
    attempt  = float(session.get("attempt_count", 1) or 1)
    dur_ms   = float(session.get("session_dur_ms", 0) or 0)
    inp_len  = float(session.get("input_max_len", 0) or 0)
    proto    = (session.get("proto", "") or "").lower()
    cmd      = session.get("cmd", "") or ""

    log_dur  = math.log1p(dur_ms)

    return np.array([
        attempt,
        log_dur,
        inp_len,
        1.0 if proto == "http"   else 0.0,
        1.0 if proto == "telnet" else 0.0,
        1.0 if proto == "mqtt"   else 0.0,
        float(len(cmd)),
    ], dtype=float)


class AnomalyDetector:
    """
    Stateful detector that keeps a rolling history of session feature vectors
    and flags outliers via Z-score distance.
    """

    def __init__(self,
                 zscore_threshold: float = ZSCORE_THRESHOLD,
                 history_size: int = HISTORY_SIZE):
        self._threshold  = zscore_threshold
        self._history: Deque[np.ndarray] = deque(maxlen=history_size)
        self._new_since_dbscan = 0

    # ------------------------------------------------------------------

    def score(self, session: dict) -> Tuple[float, bool]:
        """
        Return (z_score, is_anomaly) for a single session.
        Also appends the session to internal history.
        """
        vec = _session_to_vector(session)
        self._history.append(vec)
        self._new_since_dbscan += 1

        if len(self._history) < 10:
            # Not enough data — cannot score
            return (0.0, False)

        matrix = np.array(self._history)
        centroid = matrix.mean(axis=0)
        std      = matrix.std(axis=0) + 1e-9   # avoid /0

        z = float(np.max(np.abs((vec - centroid) / std)))
        return (z, z > self._threshold)

    def classify(self, session: dict) -> Optional[Tuple[PatternID, float]]:
        """
        If the session is anomalous, return (ZERO_DAY_ANOMALY, confidence).
        Confidence is scaled from threshold to threshold+3σ → [0.55, 0.85].
        """
        z, is_anomaly = self.score(session)
        if not is_anomaly:
            return None
        # Clamp confidence: 0.55 at exactly the threshold, max 0.85
        excess = min(z - self._threshold, 3.0)
        conf = 0.55 + 0.30 * (excess / 3.0)
        return (PatternID.ZERO_DAY_ANOMALY, round(conf, 3))

    # ------------------------------------------------------------------

    def dbscan_outliers(self) -> List[int]:
        """
        Run DBSCAN over current history; return indices of outlier sessions (-1 label).
        Returns empty list if DBSCAN unavailable or insufficient data.
        """
        if not _DBSCAN_AVAILABLE or len(self._history) < DBSCAN_MIN_SAMPLES * 2:
            return []

        matrix = np.array(self._history)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(matrix)

        labels = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES).fit_predict(scaled)
        return [i for i, lbl in enumerate(labels) if lbl == -1]

    def should_run_dbscan(self) -> bool:
        return self._new_since_dbscan >= DBSCAN_BATCH_SIZE

    def reset_dbscan_counter(self) -> None:
        self._new_since_dbscan = 0


# ── Module-level singleton ────────────────────────────────────────────────────
_detector = AnomalyDetector()


def classify_anomaly(session: dict) -> Optional[Tuple[PatternID, float]]:
    """Convenience wrapper around the module-level AnomalyDetector."""
    return _detector.classify(session)


def run_dbscan_if_due() -> List[int]:
    """Run DBSCAN and reset counter if enough new sessions have arrived."""
    if _detector.should_run_dbscan():
        _detector.reset_dbscan_counter()
        return _detector.dbscan_outliers()
    return []
