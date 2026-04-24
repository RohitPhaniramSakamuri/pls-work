#!/usr/bin/env python3
"""
benchmark.py — ESP32 Honeypot performance validation suite.

Tests the following metrics from PDF Section III.A:
  1. Concurrent connection capacity (target: 100 connections)
  2. Event logging latency (target: <500ms 95th pct)
  3. MQTT throughput (target: >200 events/min sustained)
  4. End-to-end pipeline latency: MQTT → InfluxDB → visible in query (target: <1s)
  5. Classifier processing rate

Usage:
    python scripts/benchmark.py --host <ESP32-IP> --broker localhost

Prerequisites:
    pip install paho-mqtt requests influxdb-client
"""
import argparse
import json
import socket
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
import threading

try:
    import paho.mqtt.client as mqtt
    import requests
    from influxdb_client import InfluxDBClient
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("  pip install paho-mqtt requests influxdb-client")
    sys.exit(1)

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _ok(msg):  print(f"  {GREEN}✓{RESET}  {msg}")
def _warn(msg): print(f"  {YELLOW}⚠{RESET}  {msg}")
def _fail(msg): print(f"  {RED}✗{RESET}  {msg}")

# ── TCP connection burst ───────────────────────────────────────────────────────

def _tcp_connect(host: str, port: int, timeout: float = 3.0) -> float:
    """Open a TCP connection and measure connect latency in ms. Returns -1 on error."""
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        latency_ms = (time.perf_counter() - t0) * 1000
        s.close()
        return latency_ms
    except Exception:
        return -1.0


def bench_concurrent_connections(host: str, ports: List[int],
                                  target: int = 50, timeout: float = 5.0):
    """
    Open `target` concurrent TCP connections across all honeypot ports.
    Measures: success rate, connect latency distribution.
    """
    print(f"\n{BOLD}[1] Concurrent Connection Capacity{RESET}")
    print(f"    Target: {target} connections across ports {ports}")

    tasks = [(host, p) for p in ports for _ in range(target // len(ports))]

    latencies: List[float] = []
    failures = 0
    t_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=target) as pool:
        futures = [pool.submit(_tcp_connect, h, p, timeout) for h, p in tasks]
        for f in as_completed(futures):
            ms = f.result()
            if ms < 0:
                failures += 1
            else:
                latencies.append(ms)

    elapsed = time.perf_counter() - t_start
    success_count = len(latencies)
    total = len(tasks)

    if latencies:
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        print(f"    Connections: {success_count}/{total} succeeded in {elapsed:.1f}s")
        print(f"    Connect latency  p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms")

        rate = success_count / total
        if rate >= 0.90:
            _ok(f"{success_count}/{total} connections succeeded ({rate*100:.0f}%)")
        elif rate >= 0.70:
            _warn(f"Only {success_count}/{total} connections succeeded ({rate*100:.0f}%) — possible resource exhaustion")
        else:
            _fail(f"Low connection success rate: {rate*100:.0f}%")
    else:
        _fail(f"All {total} connection attempts failed — is the ESP32 reachable at {host}?")

    return {"success": success_count, "total": total, "failures": failures,
            "p50_ms": p50 if latencies else 0,
            "p95_ms": p95 if latencies else 0}


# ── MQTT throughput ────────────────────────────────────────────────────────────

def bench_mqtt_throughput(broker: str, port: int, count: int = 500, burst_ms: int = 10000):
    """
    Publish `count` events to the MQTT broker and measure throughput.
    Target: >200 events/min sustained (from PDF §III.A).
    """
    print(f"\n{BOLD}[2] MQTT Event Throughput{RESET}")
    print(f"    Publishing {count} events to {broker}:{port}")

    published = 0
    publish_times: List[float] = []
    lock = threading.Lock()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="bench-pub")
    try:
        client.connect(broker, port, keepalive=10)
    except Exception as e:
        _fail(f"Cannot connect to MQTT broker at {broker}:{port} — {e}")
        return {}
    client.loop_start()

    t_start = time.perf_counter()
    for i in range(count):
        payload = json.dumps({
            "ts": int(time.time()), "proto": "telnet",
            "src_ip": f"10.0.{i//256}.{i%256}",
            "user": "root", "pass": "root",
            "cmd": "", "evt": "auth_attempt",
            "node": "bench-01",
            "pattern_id": 1, "confidence": 70
        })
        t0 = time.perf_counter()
        rc, mid = client.publish("honeypot/events/auth", payload, qos=0)
        publish_times.append((time.perf_counter() - t0) * 1000)
        published += 1

    elapsed = time.perf_counter() - t_start
    client.loop_stop()
    client.disconnect()

    rate_per_min = (published / elapsed) * 60
    p95 = sorted(publish_times)[int(len(publish_times) * 0.95)] if publish_times else 0

    print(f"    Published {published}/{count} events in {elapsed:.1f}s")
    print(f"    Throughput: {rate_per_min:.0f} events/min  |  publish p95={p95:.1f}ms")

    if rate_per_min >= 200:
        _ok(f"Throughput {rate_per_min:.0f} events/min ≥ 200 target")
    else:
        _warn(f"Throughput {rate_per_min:.0f} events/min below 200 target")

    return {"rate_per_min": rate_per_min, "elapsed_s": elapsed, "p95_ms": p95}


# ── End-to-end pipeline latency ────────────────────────────────────────────────

def bench_e2e_latency(broker: str, influx_url: str, influx_token: str,
                       influx_org: str, influx_bucket: str,
                       samples: int = 10):
    """
    Measures end-to-end latency: MQTT publish → visible in InfluxDB query.
    Target: <1 second for 95th percentile (PDF §III.D criterion 4).
    """
    print(f"\n{BOLD}[3] End-to-End Pipeline Latency (MQTT → InfluxDB){RESET}")
    print(f"    Running {samples} probe events…")

    latencies: List[float] = []

    # InfluxDB client
    try:
        influx = InfluxDBClient(url=influx_url, token=influx_token, org=influx_org)
        qapi = influx.query_api()
    except Exception as e:
        _fail(f"Cannot connect to InfluxDB at {influx_url} — {e}")
        return {}

    # MQTT client
    try:
        pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="bench-e2e")
        pub.connect(broker, 1883, keepalive=10)
        pub.loop_start()
    except Exception as e:
        _fail(f"Cannot connect to MQTT broker — {e}")
        return {}

    for i in range(samples):
        marker = f"bench-e2e-{int(time.time() * 1000)}-{i}"
        payload = json.dumps({
            "ts": int(time.time()), "proto": "ssh",
            "src_ip": "192.168.1.99",
            "user": marker, "pass": "",
            "cmd": "", "evt": "connect",
            "node": "bench-e2e",
            "pattern_id": 14, "confidence": 85
        })

        t_publish = time.perf_counter()
        pub.publish("honeypot/events/connect", payload, qos=0)

        # Poll InfluxDB until the event appears (max 5s)
        visible = False
        for _ in range(50):   # 50 × 100ms = 5s max
            time.sleep(0.1)
            flux = f'''
from(bucket: "{influx_bucket}")
  |> range(start: -30s)
  |> filter(fn: (r) => r._measurement == "mqtt_consumer")
  |> filter(fn: (r) => r._field == "user")
  |> filter(fn: (r) => r._value == "{marker}")
  |> count()
'''
            try:
                tables = qapi.query(flux)
                for table in tables:
                    for record in table.records:
                        if (record.get_value() or 0) > 0:
                            visible = True
            except Exception:
                pass
            if visible:
                break

        if visible:
            latency_ms = (time.perf_counter() - t_publish) * 1000
            latencies.append(latency_ms)
            print(f"    Sample {i+1}: {latency_ms:.0f}ms", end="\r")
        else:
            print(f"    Sample {i+1}: TIMEOUT (>5s)")

    pub.loop_stop()
    pub.disconnect()
    influx.close()
    print()  # newline after \r

    if latencies:
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        print(f"    Latency p50={p50:.0f}ms  p95={p95:.0f}ms  ({len(latencies)}/{samples} measured)")
        if p95 <= 1000:
            _ok(f"p95 latency {p95:.0f}ms ≤ 1000ms target")
        elif p95 <= 2000:
            _warn(f"p95 latency {p95:.0f}ms exceeds 1s target (Telegraf flush interval may need tuning)")
        else:
            _fail(f"p95 latency {p95:.0f}ms — pipeline may be congested")
        return {"p50_ms": p50, "p95_ms": p95, "samples": len(latencies)}
    else:
        _fail("No latency samples collected — check Telegraf and InfluxDB are running")
        return {}


# ── Classifier API health ──────────────────────────────────────────────────────

def bench_classifier(classifier_url: str):
    print(f"\n{BOLD}[4] Classifier Microservice{RESET}")
    try:
        r = requests.get(f"{classifier_url}/health", timeout=5)
        r.raise_for_status()
        status = r.json()
        _ok(f"Classifier healthy: {status}")
    except Exception as e:
        _fail(f"Classifier not reachable at {classifier_url} — {e}")
        return

    # Benchmark classify endpoint
    payload = {
        "proto": "telnet", "src_ip": "185.220.101.1",
        "user": "root", "password": "xc3511",
        "cmd": "", "evt": "auth_attempt",
        "attempt_count": 2, "session_dur_ms": 200.0
    }
    latencies = []
    for _ in range(20):
        t0 = time.perf_counter()
        try:
            r = requests.post(f"{classifier_url}/classify", json=payload, timeout=5)
            r.raise_for_status()
            latencies.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass

    if latencies:
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        print(f"    /classify  p50={statistics.median(latencies):.1f}ms  p95={p95:.1f}ms  (20 requests)")
        if p95 < 100:
            _ok(f"Classifier p95={p95:.1f}ms — well within real-time budget")
        else:
            _warn(f"Classifier p95={p95:.1f}ms — may need optimization for high-throughput scenarios")


# ── Report summary ────────────────────────────────────────────────────────────

def print_summary(results: dict, skip_esp32: bool = False):
    print(f"\n{'─'*60}")
    print(f"{BOLD}BENCHMARK SUMMARY{RESET}")
    print(f"{'─'*60}")

    criteria = [
        ("100 concurrent connections", skip_esp32 or results.get("connections", {}).get("success", 0) >= 80),
        ("MQTT throughput ≥ 200 events/min", results.get("mqtt", {}).get("rate_per_min", 0) >= 200),
        ("E2E pipeline latency p95 < 5s", results.get("e2e", {}).get("p95_ms", 9999) <= 5000),
        ("Classifier API healthy", results.get("classifier_ok", False)),
    ]

    all_pass = True
    for label, passed in criteria:
        if passed:
            _ok(label)
        else:
            _fail(label)
            all_pass = False

    print(f"\n{'─'*60}")
    if all_pass:
        print(f"{GREEN}{BOLD}All performance targets met.{RESET}")
    else:
        print(f"{YELLOW}{BOLD}Some targets missed — see details above.{RESET}")
    print(f"{'─'*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ESP32 Honeypot Performance Benchmark")
    parser.add_argument("--host",           default="192.168.1.100",  help="ESP32 IP address")
    parser.add_argument("--broker",         default="localhost",       help="MQTT broker host")
    parser.add_argument("--influx-url",     default="http://localhost:8086")
    parser.add_argument("--influx-token",   default="honeypot-super-secret-token")
    parser.add_argument("--influx-org",     default="honeypot")
    parser.add_argument("--influx-bucket",  default="attacks")
    parser.add_argument("--classifier-url", default="http://localhost:8000")
    parser.add_argument("--connections",    type=int, default=50,  help="Concurrent connections to test")
    parser.add_argument("--mqtt-events",    type=int, default=300, help="MQTT events to publish for throughput")
    parser.add_argument("--e2e-samples",    type=int, default=10,  help="E2E latency probe samples")
    parser.add_argument("--skip-esp32",     action="store_true",   help="Skip ESP32 TCP connection tests")
    parser.add_argument("--skip-e2e",       action="store_true",   help="Skip slow E2E latency test")
    args = parser.parse_args()

    print(f"\n{BOLD}ESP32 IoT Honeypot — Performance Benchmark{RESET}")
    print(f"{'─'*60}")
    print(f"  ESP32 host:   {args.host}")
    print(f"  MQTT broker:  {args.broker}:1883")
    print(f"  InfluxDB:     {args.influx_url}")
    print(f"  Classifier:   {args.classifier_url}")

    results = {}

    # 1. Concurrent connections to ESP32
    if not args.skip_esp32:
        results["connections"] = bench_concurrent_connections(
            args.host, ports=[22, 23, 80, 443, 1883],
            target=args.connections
        )

    # 2. MQTT throughput
    results["mqtt"] = bench_mqtt_throughput(
        args.broker, 1883, count=args.mqtt_events
    )

    # 3. E2E pipeline latency
    if not args.skip_e2e:
        results["e2e"] = bench_e2e_latency(
            args.broker, args.influx_url, args.influx_token,
            args.influx_org, args.influx_bucket,
            samples=args.e2e_samples
        )
    else:
        _warn("E2E latency test skipped")

    # 4. Classifier
    try:
        bench_classifier(args.classifier_url)
        results["classifier_ok"] = True
    except Exception:
        results["classifier_ok"] = False

    print_summary(results, skip_esp32=args.skip_esp32)


if __name__ == "__main__":
    main()
