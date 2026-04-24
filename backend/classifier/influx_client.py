"""
influx_client.py — InfluxDB 2.x read/write helpers for the classifier.

Reads raw honeypot events from the 'attacks' bucket (written by Telegraf),
and writes classifier enrichment (pattern_id, confidence, group) back as
a separate measurement 'classified_events'.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from influxdb_client import InfluxDBClient, WriteOptions
from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client.client.flux_table import FluxRecord

# ── Connection config (override with env vars) ────────────────────────────────
INFLUX_URL    = os.getenv("INFLUX_URL",   "http://influxdb:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN", "honeypot-super-secret-token")
INFLUX_ORG    = os.getenv("INFLUX_ORG",  "honeypot")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET","attacks")

# How many minutes of new events to pull on each scheduler tick
POLL_WINDOW_MINUTES = int(os.getenv("POLL_WINDOW_MINUTES", "2"))


def _make_client() -> InfluxDBClient:
    return InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)


# ── Read helpers ──────────────────────────────────────────────────────────────

def fetch_recent_events(window_minutes: int = POLL_WINDOW_MINUTES) -> List[Dict[str, Any]]:
    """
    Pull the last `window_minutes` of mqtt_consumer records from InfluxDB.
    Returns a list of flat dicts suitable for passing to the classifier.
    """
    flux = f"""
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -{window_minutes}m)
  |> filter(fn: (r) => r._measurement == "mqtt_consumer")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> limit(n: 500)
"""
    sessions: List[Dict[str, Any]] = []
    with _make_client() as client:
        tables = client.query_api().query(flux)
        for table in tables:
            for record in table.records:
                row = dict(record.values)
                # Flatten _time into a usable key
                row["_ts_influx"] = row.get("_time")
                sessions.append(row)
    return sessions


def fetch_ip_timestamps(window_hours: int = 2) -> Dict[str, List[float]]:
    """
    Return {src_ip: [unix_timestamp, ...]} for Hawkes timing analysis.
    Uses the influxdb ingestion time (_time) as the timestamp source
    (ESP32 millis-based ts is not reliable for timing analysis).
    """
    flux = f"""
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -{window_hours}h)
  |> filter(fn: (r) => r._measurement == "mqtt_consumer")
  |> filter(fn: (r) => r._field == "src_ip")
  |> keep(columns: ["_time", "_value"])
  |> sort(columns: ["_time"])
"""
    ip_ts: Dict[str, List[float]] = {}
    with _make_client() as client:
        tables = client.query_api().query(flux)
        for table in tables:
            for record in table.records:
                ip  = str(record.get_value() or "")
                ts  = record.get_time()
                if ip and ts:
                    unix_ts = ts.timestamp()
                    ip_ts.setdefault(ip, []).append(unix_ts)
    return ip_ts


# ── Write helpers ─────────────────────────────────────────────────────────────

def write_classifications(rows: List[Dict[str, Any]]) -> None:
    """
    Write a batch of classifier results to the 'classified_events' measurement.

    Each row must contain:
        src_ip, proto, evt, pattern_id, pattern_name, group,
        confidence, botnet_family, mitre_technique,
        session_id (optional), _ts_influx (datetime, optional)
    """
    if not rows:
        return

    from influxdb_client.domain.write_precision import WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS

    records = []
    now = datetime.now(timezone.utc)

    for r in rows:
        ts = r.get("_ts_influx") or now
        # Use hashed IP as the tagged identifier (privacy-preserving per PDF §II.D)
        # Raw IP kept only in a field (not indexed as tag) for debugging; omit in prod.
        ip_hash = str(r.get("src_ip_hash", ""))
        record = {
            "measurement": "classified_events",
            "tags": {
                "src_ip_hash":    ip_hash,
                "src_ip":         str(r.get("src_ip", "")),   # raw IP tag — remove in prod
                "proto":          str(r.get("proto", "")),
                "pattern_id":     str(r.get("pattern_id", 0)),
                "pattern_name":   str(r.get("pattern_name", "UNKNOWN")),
                "group":          str(r.get("group", "?")),
                "botnet_family":  str(r.get("botnet_family", "")),
                "mitre_technique":str(r.get("mitre_technique", "")),
                "country_code":   str(r.get("country_code", "XX")),
            },
            "fields": {
                "confidence":    float(r.get("confidence", 0.0)),
                "evt":           str(r.get("evt", "")),
                "session_id":    str(r.get("session_id", "")),
                "country":       str(r.get("country", "Unknown")),
                "lat":           float(r.get("lat", 0.0)),
                "lon":           float(r.get("lon", 0.0)),
                "org":           str(r.get("org", "")),
                "hmm_classified":bool(r.get("hmm_classified", False)),
            },
            "time": ts,
        }
        records.append(record)

    with _make_client() as client:
        write_api = client.write_api(write_options=SYNCHRONOUS)
        write_api.write(
            bucket=INFLUX_BUCKET,
            org=INFLUX_ORG,
            record=records,
            write_precision=WritePrecision.NS,
        )


def write_timing_classifications(results: Dict[str, Any]) -> None:
    """
    Write Hawkes/timing classification results (Group E) to InfluxDB.
    results: { "src_ip": (PatternID, confidence), ... }
    """
    from influxdb_client.domain.write_precision import WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    from patterns import PATTERNS

    now = datetime.now(timezone.utc)
    records = []

    for ip, (pattern_id, confidence) in results.items():
        pat = PATTERNS.get(int(pattern_id))
        record = {
            "measurement": "classified_events",
            "tags": {
                "src_ip":         ip,
                "proto":          "any",
                "pattern_id":     str(int(pattern_id)),
                "pattern_name":   pat.name       if pat else "UNKNOWN",
                "group":          pat.group      if pat else "E",
                "botnet_family":  pat.botnet_family  if pat else "",
                "mitre_technique":pat.mitre_technique if pat else "",
            },
            "fields": {
                "confidence": float(confidence),
                "evt":        "timing_classification",
                "session_id": "",
            },
            "time": now,
        }
        records.append(record)

    if not records:
        return

    with _make_client() as client:
        write_api = client.write_api(write_options=SYNCHRONOUS)
        write_api.write(
            bucket=INFLUX_BUCKET,
            org=INFLUX_ORG,
            record=records,
            write_precision=WritePrecision.NS,
        )


# ── Stats query ───────────────────────────────────────────────────────────────

def fetch_pattern_summary(window_hours: int = 24) -> List[Dict[str, Any]]:
    """
    Return aggregate counts per pattern_name over the last `window_hours`.
    """
    flux = f"""
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -{window_hours}h)
  |> filter(fn: (r) => r._measurement == "classified_events")
  |> filter(fn: (r) => r._field == "confidence")
  |> group(columns: ["pattern_name", "group"])
  |> count()
  |> rename(columns: {{_value: "count"}})
"""
    summary: List[Dict[str, Any]] = []
    with _make_client() as client:
        tables = client.query_api().query(flux)
        for table in tables:
            for record in table.records:
                summary.append({
                    "pattern_name": record.values.get("pattern_name", ""),
                    "group":        record.values.get("group", ""),
                    "count":        record.get_value(),
                })
    return summary
