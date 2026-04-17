"""
hawkes_classifier.py — Group E timing-based pattern detection.

Uses inter-arrival statistics over a rolling 2-hour window per src_ip
to classify into patterns 40-43:
  40: HAWKES_BURST_A    — >20 events/min burst then silence >30 min
  41: HAWKES_BURST_B    — 5-15/min sustained over >2 hours
  42: HAWKES_PERIODIC   — regular inter-arrival, CV < 0.3
  43: DIURNAL_NIGHT     — attacks concentrate 00:00-06:00 UTC
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np

from patterns import PatternID


# ── Thresholds ────────────────────────────────────────────────────────────────
BURST_A_RATE_THRESH   = 20      # events/min to qualify as burst
BURST_A_SILENCE_SECS  = 1800    # 30 min silence after burst
BURST_B_RATE_MIN      = 5       # events/min lower bound
BURST_B_RATE_MAX      = 15      # events/min upper bound
BURST_B_DURATION_SECS = 7200    # must sustain for 2+ hours
PERIODIC_CV_THRESH    = 0.30    # CV < 0.3 → periodic
DIURNAL_NIGHT_START   = 0       # 00:00 UTC
DIURNAL_NIGHT_END     = 6       # 06:00 UTC
DIURNAL_NIGHT_FRAC    = 0.70    # ≥70% of events must be in night window


def _cv(arr: np.ndarray) -> float:
    """Coefficient of variation (std/mean); 0 if mean == 0."""
    if len(arr) < 2:
        return 0.0
    m = float(np.mean(arr))
    if m == 0:
        return 0.0
    return float(np.std(arr, ddof=1)) / m


def _events_per_minute(timestamps_s: List[float], window_s: float = 300) -> float:
    """Peak events/min measured over any 5-min sliding window."""
    if len(timestamps_s) < 2:
        return 0.0
    ts = sorted(timestamps_s)
    max_rate = 0.0
    l = 0
    for r in range(len(ts)):
        while ts[r] - ts[l] > window_s:
            l += 1
        count = r - l + 1
        rate = count / (window_s / 60.0)
        if rate > max_rate:
            max_rate = rate
    return max_rate


def _mean_rate(timestamps_s: List[float]) -> float:
    """Overall mean events/min over the full span."""
    if len(timestamps_s) < 2:
        return 0.0
    span = timestamps_s[-1] - timestamps_s[0]
    if span <= 0:
        return 0.0
    return (len(timestamps_s) - 1) / (span / 60.0)


def _silence_after_burst(timestamps_s: List[float],
                          burst_end_idx: int) -> float:
    """Seconds of silence after the last burst event."""
    if burst_end_idx >= len(timestamps_s) - 1:
        # burst is at the end of the window — measure against wall clock
        now = datetime.now(timezone.utc).timestamp()
        return now - timestamps_s[burst_end_idx]
    return timestamps_s[burst_end_idx + 1] - timestamps_s[burst_end_idx]


def _find_burst_end(timestamps_s: List[float],
                    window_s: float = 300) -> Optional[int]:
    """Return the index of the last event inside the highest-rate 5-min window."""
    if len(timestamps_s) < 2:
        return None
    ts = sorted(timestamps_s)
    best_rate = 0.0
    best_r = None
    l = 0
    for r in range(len(ts)):
        while ts[r] - ts[l] > window_s:
            l += 1
        count = r - l + 1
        rate = count / (window_s / 60.0)
        if rate > best_rate:
            best_rate = rate
            best_r = r
    return best_r


def _diurnal_fraction(timestamps_s: List[float]) -> float:
    """Fraction of events that fall between 00:00 and 06:00 UTC."""
    if not timestamps_s:
        return 0.0
    night = sum(
        1 for t in timestamps_s
        if DIURNAL_NIGHT_START <= datetime.fromtimestamp(t, tz=timezone.utc).hour < DIURNAL_NIGHT_END
    )
    return night / len(timestamps_s)


# ── Public interface ──────────────────────────────────────────────────────────

def classify_timing(
    timestamps_s: List[float],
    min_events: int = 5,
) -> Optional[Tuple[PatternID, float]]:
    """
    Given a list of Unix timestamps (seconds) for one src_ip over a ~2 h window,
    return (PatternID, confidence) for Group E patterns or None.
    """
    if len(timestamps_s) < min_events:
        return None

    ts_sorted = sorted(timestamps_s)

    # ── Pattern 43: DIURNAL_NIGHT ─────────────────────────────────────────────
    frac = _diurnal_fraction(ts_sorted)
    if frac >= DIURNAL_NIGHT_FRAC and len(ts_sorted) >= 10:
        conf = 0.60 + 0.30 * ((frac - DIURNAL_NIGHT_FRAC) / (1.0 - DIURNAL_NIGHT_FRAC))
        return (PatternID.DIURNAL_NIGHT, round(min(conf, 0.90), 3))

    inter_arrivals = np.diff(ts_sorted).astype(float)
    cv = _cv(inter_arrivals)
    peak_rate = _events_per_minute(ts_sorted)
    mean_rate = _mean_rate(ts_sorted)
    span_s = ts_sorted[-1] - ts_sorted[0]

    # ── Pattern 42: HAWKES_PERIODIC ───────────────────────────────────────────
    if cv < PERIODIC_CV_THRESH and len(inter_arrivals) >= 5:
        conf = 0.70 + 0.25 * ((PERIODIC_CV_THRESH - cv) / PERIODIC_CV_THRESH)
        return (PatternID.HAWKES_PERIODIC, round(min(conf, 0.95), 3))

    # ── Pattern 40: HAWKES_BURST_A ────────────────────────────────────────────
    if peak_rate >= BURST_A_RATE_THRESH:
        burst_end_idx = _find_burst_end(ts_sorted)
        silence = _silence_after_burst(ts_sorted, burst_end_idx) if burst_end_idx is not None else 0
        if silence >= BURST_A_SILENCE_SECS:
            # Confidence scales with how far peak_rate exceeds threshold
            rate_factor = min((peak_rate - BURST_A_RATE_THRESH) / BURST_A_RATE_THRESH, 1.0)
            conf = 0.75 + 0.20 * rate_factor
            return (PatternID.HAWKES_BURST_A, round(conf, 3))

    # ── Pattern 41: HAWKES_BURST_B ────────────────────────────────────────────
    if (BURST_B_RATE_MIN <= mean_rate <= BURST_B_RATE_MAX
            and span_s >= BURST_B_DURATION_SECS):
        # Confidence based on how centred the mean rate is in the [5,15] band
        centre = (BURST_B_RATE_MIN + BURST_B_RATE_MAX) / 2.0
        deviation = abs(mean_rate - centre) / ((BURST_B_RATE_MAX - BURST_B_RATE_MIN) / 2.0)
        conf = 0.70 + 0.20 * (1.0 - deviation)
        return (PatternID.HAWKES_BURST_B, round(conf, 3))

    return None


# ── Batch helper used by the scheduler ───────────────────────────────────────

def classify_all_ips(
    ip_events: Dict[str, List[float]],
) -> Dict[str, Tuple[PatternID, float]]:
    """
    Classify timing for every ip in ip_events.
    ip_events: { "1.2.3.4": [unix_ts, ...], ... }
    Returns: { "1.2.3.4": (PatternID, confidence), ... }  — only matched IPs.
    """
    results: Dict[str, Tuple[PatternID, float]] = {}
    for ip, ts_list in ip_events.items():
        hit = classify_timing(ts_list)
        if hit:
            results[ip] = hit
    return results
