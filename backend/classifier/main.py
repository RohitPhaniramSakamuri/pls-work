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
from hmm_classifier import classify_sessions_hmm
from heuristic_rules import classify
from geoip_enricher import enrich_batch
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

        # ── Step 1: Heuristic + anomaly classification ─────────────────────
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

        # ── Step 2: HMM multi-stage sequence analysis ──────────────────────
        hmm_results = classify_sessions_hmm(sessions, group_by="session_id")
        if hmm_results:
            log.info(f"  HMM classified {len(hmm_results)} sessions")
            # Overlay HMM result where it increases confidence
            for row in enriched:
                key = str(row.get("session_id", ""))
                if key in hmm_results:
                    hmm_pid, hmm_conf = hmm_results[key]
                    if hmm_conf > float(row.get("confidence", 0)):
                        pat = PATTERNS.get(int(hmm_pid))
                        row["pattern_id"]      = int(hmm_pid)
                        row["pattern_name"]    = pat.name            if pat else "UNKNOWN"
                        row["group"]           = pat.group           if pat else "?"
                        row["confidence"]      = hmm_conf
                        row["botnet_family"]   = pat.botnet_family   if pat else ""
                        row["mitre_technique"] = pat.mitre_technique if pat else ""
                        row["hmm_classified"]  = True

        # ── Step 3: GeoIP enrichment + IP hashing ──────────────────────────
        enriched = enrich_batch(enriched)
        log.info(f"  GeoIP/hash enrichment done for {len(enriched)} records")

        write_classifications(enriched)
        log.info(f"  Wrote {len(enriched)} enriched records")

        # ── Step 4: Group E Hawkes timing ───────────────────────────────────
        ip_ts = fetch_ip_timestamps(window_hours=2)
        timing_results = classify_all_ips(ip_ts)
        if timing_results:
            write_timing_classifications(timing_results)
            log.info(f"  Timing classifications: {len(timing_results)}")

        # ── Step 5: Periodic DBSCAN ─────────────────────────────────────────
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
