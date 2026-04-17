"""
main.py — FastAPI classifier microservice.

Scheduler: every 60s, pull new events from InfluxDB, run all classifiers,
write enriched results back.

REST endpoints:
  GET /health
  GET /patterns/summary          → aggregate counts last 24h
  GET /patterns/{id}             → single pattern metadata
  GET /patterns/{id}/recent      → most recent classified events for that pattern
  POST /classify                 → classify a single session on demand
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from anomaly_detector import classify_anomaly, run_dbscan_if_due
from hawkes_classifier import classify_all_ips
from heuristic_rules import classify
from influx_client import (
    fetch_ip_timestamps,
    fetch_pattern_summary,
    fetch_recent_events,
    write_classifications,
    write_timing_classifications,
)
from patterns import PATTERNS, PATTERN_BY_NAME, PatternID

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ── Scheduler job ─────────────────────────────────────────────────────────────

def _classify_batch() -> None:
    log.info("Classifier tick: fetching recent events…")
    try:
        sessions = fetch_recent_events()
        log.info(f"  {len(sessions)} sessions fetched")
        if not sessions:
            return

        enriched: List[Dict[str, Any]] = []
        for s in sessions:
            pid, conf = classify(s)
            # Fall through to anomaly detector if unclassified
            if pid == PatternID.ZERO_DAY_ANOMALY:
                result = classify_anomaly(s)
                if result:
                    pid, conf = result

            pat = PATTERNS.get(int(pid))
            enriched.append({
                **s,
                "pattern_id":     int(pid),
                "pattern_name":   pat.name            if pat else "UNKNOWN",
                "group":          pat.group           if pat else "?",
                "confidence":     conf,
                "botnet_family":  pat.botnet_family   if pat else "",
                "mitre_technique":pat.mitre_technique if pat else "",
            })

        write_classifications(enriched)
        log.info(f"  Wrote {len(enriched)} enriched records")

        # Group E: Hawkes timing
        ip_ts = fetch_ip_timestamps(window_hours=2)
        timing_results = classify_all_ips(ip_ts)
        if timing_results:
            write_timing_classifications(timing_results)
            log.info(f"  Timing classifications: {len(timing_results)}")

        # Periodic DBSCAN
        outliers = run_dbscan_if_due()
        if outliers:
            log.info(f"  DBSCAN outlier indices: {outliers}")

    except Exception as exc:
        log.error(f"Classifier tick error: {exc}", exc_info=True)


# ── App lifecycle ─────────────────────────────────────────────────────────────

_scheduler = BackgroundScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _scheduler.add_job(_classify_batch, "interval", seconds=60, id="classify_batch")
    _scheduler.start()
    log.info("Classifier scheduler started (60s interval)")
    yield
    _scheduler.shutdown(wait=False)
    log.info("Classifier scheduler stopped")


app = FastAPI(title="Honeypot Pattern Classifier", version="2.0.0", lifespan=lifespan)


# ── Request/response models ───────────────────────────────────────────────────

class SessionIn(BaseModel):
    proto:            Optional[str]   = ""
    src_ip:           Optional[str]   = ""
    user:             Optional[str]   = ""
    password:         Optional[str]   = ""   # 'pass' is a Python keyword
    cmd:              Optional[str]   = ""
    evt:              Optional[str]   = ""
    attempt_count:    Optional[int]   = 1
    session_dur_ms:   Optional[float] = 0.0
    input_max_len:    Optional[int]   = 0
    confidence:       Optional[int]   = 0
    pattern_id:       Optional[int]   = 0


class ClassifyOut(BaseModel):
    pattern_id:      int
    pattern_name:    str
    group:           str
    confidence:      float
    botnet_family:   str
    mitre_technique: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "scheduler_running": _scheduler.running}


@app.post("/classify", response_model=ClassifyOut)
def classify_one(body: SessionIn):
    session = body.model_dump()
    # Map 'password' back to 'pass' for the rules engine
    session["pass"] = session.pop("password", "")
    pid, conf = classify(session)
    if pid == PatternID.ZERO_DAY_ANOMALY:
        result = classify_anomaly(session)
        if result:
            pid, conf = result
    pat = PATTERNS.get(int(pid))
    return ClassifyOut(
        pattern_id      = int(pid),
        pattern_name    = pat.name            if pat else "UNKNOWN",
        group           = pat.group           if pat else "?",
        confidence      = conf,
        botnet_family   = pat.botnet_family   if pat else "",
        mitre_technique = pat.mitre_technique if pat else "",
    )


@app.get("/patterns/summary")
def pattern_summary(hours: int = 24):
    try:
        data = fetch_pattern_summary(window_hours=hours)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"window_hours": hours, "patterns": data}


@app.get("/patterns/{pid}")
def pattern_detail(pid: int):
    pat = PATTERNS.get(pid)
    if not pat:
        raise HTTPException(status_code=404, detail=f"Pattern {pid} not found")
    return {
        "id":               int(pat.id),
        "name":             pat.name,
        "group":            pat.group,
        "protocols":        pat.protocols,
        "primary_indicator":pat.primary_indicator,
        "botnet_family":    pat.botnet_family,
        "mitre_technique":  pat.mitre_technique,
    }


@app.get("/patterns")
def list_patterns():
    return [
        {
            "id":    int(p.id),
            "name":  p.name,
            "group": p.group,
        }
        for p in PATTERNS.values()
    ]
