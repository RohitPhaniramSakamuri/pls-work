"""
hmm_classifier.py — Hidden Markov Model for post-exploitation command sequence analysis.

Per PDF Section II.D: "High-level behavioral events aggregate temporal sequences
into attack campaign classifications."

Model description
-----------------
3 hidden states:
  S0 = RECON       — port scanning, banner grabbing, service enumeration
  S1 = AUTH        — credential brute-forcing, authentication attempts
  S2 = POSTEXPLOIT — command execution, payload delivery, persistence

7 observable event types (emission symbols):
  0 = connect
  1 = auth_attempt
  2 = auth_success
  3 = command
  4 = exploit
  5 = heartbeat
  6 = other/unknown

Transition matrix A[i][j] = P(state_j | state_i):
  Built from empirical IoT botnet kill-chain literature (Mirai/Hajime/Gafgyt).

Emission matrix B[state][obs] = P(obs | state):
  Derived from honeypot dataset analysis (Williams & Patterson, 2020).

Viterbi decoding maps an observed event sequence to the most likely state path,
enabling multi-stage attack phase detection even with partial observations.

Classification result maps to pattern taxonomy:
  Sequence ending in POSTEXPLOIT → C2_CALLBACK_ATTEMPT (pattern 37) or WGET_DROPPER (31)
  Sequence staying in AUTH       → MIRAI_DEFAULT_CREDS (1) or GENERIC_DICT_FAST (9)
  Sequence ending in RECON only  → BANNER_GRAB_ONLY (14) or PORT_SCAN_SEQUENTIAL (13)
"""
from __future__ import annotations

import logging
import math
from typing import Dict, List, Optional, Tuple

import numpy as np

from patterns import PatternID

log = logging.getLogger(__name__)

# ── HMM parameters (empirically derived from IoT botnet literature) ───────────

# State labels
STATE_RECON       = 0
STATE_AUTH        = 1
STATE_POSTEXPLOIT = 2
N_STATES          = 3

# Observation labels
OBS_CONNECT       = 0
OBS_AUTH_ATTEMPT  = 1
OBS_AUTH_SUCCESS  = 2
OBS_COMMAND       = 3
OBS_EXPLOIT       = 4
OBS_HEARTBEAT     = 5
OBS_OTHER         = 6
N_OBS             = 7

# Initial state probabilities (π)
# Most attacks start with reconnaisance
PI = np.array([0.65, 0.30, 0.05])

# Transition matrix A[from][to]
# Recon can stay in recon or move to auth; auth can succeed to postexploit
A = np.array([
    # → RECON   AUTH    POSTEXPLOIT
    [  0.60,    0.35,   0.05   ],  # from RECON
    [  0.10,    0.65,   0.25   ],  # from AUTH
    [  0.05,    0.10,   0.85   ],  # from POSTEXPLOIT
])

# Emission matrix B[state][obs]
B = np.array([
    #  conn   auth_att  auth_suc  cmd    exploit  hbeat  other
    [  0.40,   0.25,    0.02,    0.05,   0.05,   0.15,  0.08 ],  # RECON
    [  0.10,   0.55,    0.15,    0.05,   0.05,   0.05,  0.05 ],  # AUTH
    [  0.05,   0.05,    0.10,    0.50,   0.20,   0.03,  0.07 ],  # POSTEXPLOIT
])

# Add small floor to avoid log(0)
_EPS = 1e-9
LOG_PI = np.log(PI + _EPS)
LOG_A  = np.log(A  + _EPS)
LOG_B  = np.log(B  + _EPS)


# ── Event-type → observation index mapping ───────────────────────────────────

_EVT_TO_OBS: Dict[str, int] = {
    "connect":      OBS_CONNECT,
    "auth_attempt": OBS_AUTH_ATTEMPT,
    "auth_success": OBS_AUTH_SUCCESS,
    "command":      OBS_COMMAND,
    "exploit":      OBS_EXPLOIT,
    "heartbeat":    OBS_HEARTBEAT,
}


def _evt_to_obs(evt: str) -> int:
    return _EVT_TO_OBS.get((evt or "").lower(), OBS_OTHER)


# ── Viterbi algorithm ─────────────────────────────────────────────────────────

def viterbi(obs_seq: List[int]) -> Tuple[List[int], float]:
    """
    Viterbi decoding: returns (most_likely_state_path, log_probability).
    obs_seq: list of observation indices (0..N_OBS-1)
    """
    T = len(obs_seq)
    if T == 0:
        return [], -math.inf

    # delta[t][s] = max log-prob of any state sequence ending at state s at time t
    delta = np.full((T, N_STATES), -math.inf)
    psi   = np.zeros((T, N_STATES), dtype=int)

    # Initialise
    delta[0] = LOG_PI + LOG_B[:, obs_seq[0]]

    # Recursion
    for t in range(1, T):
        for s in range(N_STATES):
            probs   = delta[t - 1] + LOG_A[:, s]
            psi[t][s]   = int(np.argmax(probs))
            delta[t][s] = probs[psi[t][s]] + LOG_B[s, obs_seq[t]]

    # Backtrack
    path = [0] * T
    path[T - 1] = int(np.argmax(delta[T - 1]))
    log_prob = delta[T - 1][path[T - 1]]
    for t in range(T - 2, -1, -1):
        path[t] = psi[t + 1][path[t + 1]]

    return path, float(log_prob)


# ── Session sequence classifier ───────────────────────────────────────────────

def classify_sequence(
    events: List[Dict],
    min_events: int = 3,
) -> Optional[Tuple[PatternID, float]]:
    """
    Given a list of event dicts (sorted by time) for one session/IP,
    run Viterbi and map the final HMM state to a PatternID.

    Returns (PatternID, confidence) or None if sequence is too short.
    """
    if len(events) < min_events:
        return None

    obs_seq = [_evt_to_obs(e.get("evt", "")) for e in events]
    path, log_prob = viterbi(obs_seq)

    if not path:
        return None

    final_state = path[-1]
    # Count state transitions to detect multi-stage attacks
    state_counts = [path.count(s) for s in range(N_STATES)]
    total = max(sum(state_counts), 1)

    # Confidence: scale log_prob to [0.50, 0.90] range
    # Typical sequence log_prob for T=5: roughly -8 to -5
    conf = max(0.50, min(0.90, 0.50 + (log_prob + 15.0) / 20.0))

    # Map HMM terminal state to pattern
    if final_state == STATE_POSTEXPLOIT:
        # Check what kind of post-exploit activity was observed
        cmds = " ".join(str(e.get("cmd", "")) for e in events).lower()
        if "wget" in cmds or "curl" in cmds:
            return (PatternID.WGET_DROPPER, round(conf, 3))
        elif "bash" in cmds or "/dev/tcp" in cmds:
            return (PatternID.C2_CALLBACK_ATTEMPT, round(conf + 0.05, 3))
        else:
            return (PatternID.CHMOD_EXECUTE, round(conf, 3))

    elif final_state == STATE_AUTH:
        recon_fraction = state_counts[STATE_RECON] / total
        if recon_fraction > 0.3 and state_counts[STATE_POSTEXPLOIT] == 0:
            return (PatternID.GENERIC_DICT_FAST, round(conf, 3))
        return (PatternID.MIRAI_DEFAULT_CREDS, round(conf - 0.05, 3))

    else:  # STATE_RECON
        if state_counts[STATE_AUTH] == 0 and state_counts[STATE_POSTEXPLOIT] == 0:
            return (PatternID.BANNER_GRAB_ONLY, round(conf, 3))
        return (PatternID.PORT_SCAN_SEQUENTIAL, round(conf - 0.10, 3))


# ── Batch classifier — groups events by session_id or src_ip ─────────────────

def classify_sessions_hmm(
    events: List[Dict],
    group_by: str = "session_id",
) -> Dict[str, Tuple[PatternID, float]]:
    """
    Group events by session_id (or src_ip as fallback) and classify each group.
    Returns {session_key: (PatternID, confidence)} for matched sessions.
    """
    groups: Dict[str, List[Dict]] = {}
    for e in events:
        key = str(e.get(group_by, "") or e.get("src_ip", "unknown"))
        groups.setdefault(key, []).append(e)

    results: Dict[str, Tuple[PatternID, float]] = {}
    for key, seq in groups.items():
        # Sort by timestamp
        seq.sort(key=lambda x: x.get("ts", 0))
        result = classify_sequence(seq)
        if result:
            results[key] = result
            log.debug(f"HMM classified session {key}: {result[0].name} conf={result[1]:.2f}")

    return results
