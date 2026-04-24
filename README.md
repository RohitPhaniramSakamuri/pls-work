# ESP32 IoT Honeypot

A distributed IoT honeypot that runs on an ESP32, captures attacker activity across four protocols, and streams events through a full analytics pipeline with automated attack pattern classification.

```
[LAN / Internet attackers]
         |
   [ESP32 Honeypot]  — Telnet :23 | SSH :22 | HTTP :80 | MQTT :1883
         | publishes JSON events via MQTT over Wi-Fi
   [Mosquitto broker]  :1883 / :9001 (WS)
         |
   [Telegraf]  — subscribes, parses, enriches
         |
   [InfluxDB 2.x]  :8086
         |
   [Classifier service]  :8000  — 47-pattern ML pipeline
         |
   [Grafana]  :3000  — two dashboards, 10s auto-refresh
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| PlatformIO CLI (`pio`) | any recent |
| Docker + Docker Compose | Compose v2 |
| Python | 3.10+ |
| `paho-mqtt` Python library | `pip install paho-mqtt` |

Hardware: **ESP32 DevKit v1** (or compatible), USB cable.

---

## 1 — Flash the Firmware

### a. Fill in secrets

```bash
cp include/secrets.h.template include/secrets.h
```

Edit `include/secrets.h` with:
- `WIFI_SSID` / `WIFI_PASSWORD` — your network
- `MQTT_BROKER_IP` — LAN IP of the machine running Docker (e.g. `192.168.1.100`)
- `MQTT_BROKER_PORT` — `1883`
- `NODE_ID` — a short name for this device, e.g. `esp32-01`

`include/secrets.h` is gitignored and never committed.

### b. Build and flash

```bash
# Compile only (no device needed)
pio run

# Compile + flash (device must be connected via USB)
pio run --target upload

# Open serial monitor to watch live output
pio device monitor
```

Serial output shows: Wi-Fi connection status, each service binding, every captured event, and MQTT publish confirmations. Baud rate is 115200.

### c. What the firmware does

Once flashed and powered on the ESP32 listens on four ports simultaneously:

| Port | Protocol | Behaviour |
|---|---|---|
| 23 | Telnet | BusyBox v1.29.3 shell emulation. Accepts any Mirai top-100 credential as "valid" and drops into a fake `/ash` shell that responds to `uname -a`, `cat /etc/passwd`, `ls`, `id`, `whoami`, `wget`, `curl`, `cat /proc/cpuinfo`. All other commands return `sh: command not found`. Every input line is logged. |
| 22 | SSH (raw TCP) | Sends `SSH-2.0-OpenSSH_7.4` banner, reads up to 512 bytes, logs the client banner and key-exchange bytes, then closes. Low-interaction: captures scanner fingerprints without implementing real SSH. |
| 80 | HTTP | Fake router/NAS management portal. `GET /` redirects to `/login`. `POST /login` logs credentials; Mirai creds redirect to `/admin`, everything else returns "Invalid password". `/cgi-bin/` returns 200 to trigger exploit scanners. `/../../../etc/passwd` and other traversals are logged and 404'd. |
| 1883 | MQTT | Raw TCP listener that parses the CONNECT packet (client ID, username, password), logs it, sends CONNACK accepted, then logs any subsequent PUBLISH packets. Designed to lure MQTT-aware bots. |

Every event is published immediately (on auth success, command execution, exploit detection) or batched every 30 seconds in a heartbeat. MQTT publish uses exponential backoff (1 s → 2 s → 4 s → max 30 s) on failure.

On-device pattern classification (Groups A, B, D from the 47-pattern taxonomy) runs per-session and attaches `pattern_id`, `pattern_name`, `confidence`, and `session_id` to each event before it leaves the device.

---

## 2 — Start the Backend

```bash
cd backend

# Copy env template (only needed once)
cp .env.template .env
# Edit .env if you want a custom InfluxDB token — default works fine for local use

# Start all five services
docker compose up -d

# Watch startup logs
docker compose logs -f

# Check service health (wait ~60s for InfluxDB to initialise)
docker compose ps
```

All five services and their exposed ports:

| Container | Port | Purpose |
|---|---|---|
| `honeypot_mosquitto` | 1883 (MQTT), 9001 (WebSocket) | MQTT broker |
| `honeypot_influxdb` | 8086 | Time-series database |
| `honeypot_telegraf` | — | MQTT subscriber → InfluxDB writer |
| `honeypot_grafana` | 3000 | Dashboards |
| `honeypot_classifier` | 8000 | Pattern classification REST API |

Default credentials:
- **Grafana**: `admin` / `admin` → `http://localhost:3000`
- **InfluxDB**: `admin` / `adminpassword` → `http://localhost:8086`
- **InfluxDB token**: see `backend/.env` (`INFLUX_TOKEN`)

To stop everything:
```bash
docker compose down
# To also delete all stored data:
docker compose down -v
```

---

## 3 — Test Without Hardware (Simulation)

The simulation script publishes synthetic events directly to Mosquitto, so the full pipeline (Telegraf → InfluxDB → Classifier → Grafana) can be exercised without an ESP32.

```bash
pip install paho-mqtt

# Phase 1: generic attack events — auth attempts, commands, SSH grabs, MQTT publishes
python scripts/simulate_attacks.py --broker localhost --port 1883

# Phase 1 with fewer events (quick smoke test)
python scripts/simulate_attacks.py --broker localhost --port 1883 --count 20

# Phase 2: emit events for all 47 attack patterns with classifier fields populated
python scripts/simulate_attacks.py --broker localhost --port 1883 --patterns

# Phase 2: targeted patterns, more sessions, spread over time
python scripts/simulate_attacks.py \
  --broker localhost \
  --port 1883 \
  --patterns \
  --sessions 200 \
  --duration 300

# Phase 2: specific pattern IDs only (e.g. Mirai, coordinated subnet, wget dropper)
python scripts/simulate_attacks.py \
  --broker localhost \
  --port 1883 \
  --patterns \
  --pattern-ids 1,12,31,47
```

The `--patterns` flag sets `pattern_id`, `pattern_name`, `confidence`, and `session_id` on every event so the Grafana pattern dashboards populate immediately.

---

## 4 — Run the Health Check

```bash
bash scripts/check_pipeline.sh
```

This checks in order:
1. All four Docker containers are `running`
2. Mosquitto accepts a publish on port 1883
3. InfluxDB `/ping` returns 204
4. InfluxDB `attacks` bucket has data in the last hour
5. Grafana `/api/health` returns 200

Output is `[PASS]` / `[FAIL]` per check with a final summary line. Exit code 0 = all pass.

---

## 5 — Grafana Dashboards

Open `http://localhost:3000` (admin / admin).

### Honeypot Overview

The main operational dashboard. Nine panels:

| Panel | What it shows |
|---|---|
| Attack Rate | Events/minute over 24h, threshold line at 60/min |
| Protocol Breakdown | Pie chart of `proto` field (telnet / ssh / http / mqtt), last 6h |
| Top Source IPs | Table of top 20 attacker IPs by event count, last 24h |
| Top Credential Pairs | Username + password combos ranked by frequency, last 24h |
| Attack Type Distribution | Bar chart of `evt` values (auth_attempt, auth_success, command, exploit), last 6h |
| Commands Executed | Log panel — last 50 `command` events with timestamp, src_ip, command string |
| Active Attackers | Stat tile — unique src_ip count, last 1h |
| Total Events | Stat tile — total event count since deployment |
| System Heartbeat | Table of last 5 heartbeats from ESP32 nodes with free heap |

Dashboard variables (top bar):
- `$node` — multi-select filter by ESP32 node ID
- `$proto` — filter by protocol

Auto-refreshes every 10 seconds.

### Honeypot Patterns (Phase 2)

Attack pattern classification dashboard. Ten panels:

| Panel | What it shows |
|---|---|
| Pattern Distribution Heatmap | Time (1h buckets) × pattern_name (all 47), colour = event count (log scale) |
| Top 10 Active Patterns | 2×5 stat grid, colour-coded by group (A=red, B=orange, C=yellow, D=purple, E=blue) |
| Attack Kill Chain Timeline | State timeline per `session_id` — RECON → AUTH_ATTEMPT → AUTH_SUCCESS → EXPLOIT → POST_EXPLOIT |
| Pattern Confidence Distribution | Histogram of `confidence` field (0.0–1.0), colour by group |
| Botnet Family Attribution | Pie chart grouping by `botnet_family` tag (Mirai, Mozi, Hajime, Gafgyt, Satori, FBot, …) |
| MITRE ATT&CK Coverage | Bar chart of observed MITRE technique IDs with links to the ATT&CK URL |
| Zero-Day Anomaly Feed | Log panel filtered to `pattern_id == 47`, shows anomaly feature vector |
| Subnet Coordination Detector | /24 subnets where >3 IPs used identical credentials within 1h |
| Attack Velocity Sparklines | 9 sparklines, one per botnet family, showing events/hour over 24h |
| Session Kill Chain Sankey/Node Graph | Flow: source_country → protocol → pattern_group → outcome |

---

## 6 — Classifier REST API

The classifier service runs at `http://localhost:8000`. It polls InfluxDB every 60 seconds automatically, but you can also call it directly.

### Endpoints

**Health check**
```bash
curl http://localhost:8000/health
# {"status":"ok","scheduler_running":true}
```

**List all 47 patterns**
```bash
curl http://localhost:8000/patterns | python3 -m json.tool
```

**Get details for one pattern**
```bash
curl http://localhost:8000/patterns/1
# Returns: id, name, group, protocols, primary_indicator, botnet_family, mitre_technique
curl http://localhost:8000/patterns/47   # ZERO_DAY_ANOMALY
```

**Aggregate pattern counts (last 24h by default)**
```bash
curl "http://localhost:8000/patterns/summary"
curl "http://localhost:8000/patterns/summary?hours=6"
```

**Classify a single session on demand**
```bash
curl -s -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "proto": "telnet",
    "src_ip": "1.2.3.4",
    "user": "root",
    "password": "xc3511",
    "evt": "auth_attempt",
    "attempt_count": 1
  }' | python3 -m json.tool
# Returns: pattern_id, pattern_name, group, confidence, botnet_family, mitre_technique
```

**Recent events for a specific pattern**
```bash
curl http://localhost:8000/patterns/31/recent   # WGET_DROPPER
```

### Classification pipeline (what runs every 60s)

1. **Heuristic rules** — deterministic matching of credential combos, HTTP paths, command sequences (Groups A–D, patterns 1–39)
2. **Anomaly detector** — Z-score baseline + DBSCAN for pattern 47 (ZERO_DAY_ANOMALY) if heuristics return unknown
3. **HMM classifier** — Viterbi decoding over the event sequence per `session_id` to detect kill-chain stage progression; overlays heuristic result if HMM confidence is higher
4. **GeoIP enrichment** — resolves `src_ip` to `country`, `country_code`, `lat`, `lon`, `org` via ip-api.com (LRU-cached, rate-limited); stores a SHA-256 + daily-rotating-salt hash of the raw IP
5. **Hawkes timing classifier** — for Groups E (patterns 40–43): computes coefficient of variation (CV) and burst score over a 2-hour rolling window per source IP to identify burst-A, burst-B, periodic, and diurnal patterns

Results are written back to InfluxDB with `pattern_id`, `pattern_name`, `botnet_family`, and `mitre_technique` as tags/fields.

---

## 7 — MQTT Topic Schema

Events flow from the ESP32 (or simulation script) into Mosquitto, then Telegraf picks them up and writes to InfluxDB.

| Topic | Event type |
|---|---|
| `honeypot/events/auth` | Auth attempts and successes |
| `honeypot/events/connect` | New TCP connections |
| `honeypot/events/command` | Post-auth command execution |
| `honeypot/events/exploit` | Detected exploit attempt |
| `honeypot/events/heartbeat` | 30-second system stats from ESP32 |

**Phase 1 payload** (from real firmware):
```json
{
  "ts": 1700000000,
  "proto": "telnet",
  "src_ip": "1.2.3.4",
  "user": "admin",
  "pass": "admin",
  "cmd": "",
  "evt": "auth_attempt",
  "node": "esp32-01"
}
```

**Phase 2 payload** (adds classifier fields):
```json
{
  "ts": 1700000000,
  "proto": "telnet",
  "src_ip": "1.2.3.4",
  "user": "root",
  "pass": "xc3511",
  "cmd": "",
  "evt": "auth_attempt",
  "node": "esp32-01",
  "pattern_id": 1,
  "pattern_name": "MIRAI_DEFAULT_CREDS",
  "confidence": 0.92,
  "session_id": "a3f2c1",
  "attempt_num": 1,
  "session_duration_ms": 340
}
```

You can publish directly to the broker for manual testing:
```bash
mosquitto_pub -h localhost -p 1883 \
  -t honeypot/events/auth \
  -m '{"ts":1700000000,"proto":"telnet","src_ip":"10.0.0.1","user":"root","pass":"xc3511","evt":"auth_attempt","node":"test"}'
```

---

## 8 — The 47 Attack Pattern Taxonomy

Patterns are grouped A–E. The on-device classifier covers A, B, D. The backend classifier adds C (exploit payloads), E (timing), and pattern 47 (anomaly).

| Group | Patterns | Description |
|---|---|---|
| A (1–12) | Credential brute force | Mirai variants, Mozi, Hajime, Gafgyt, Satori, FBot, generic dictionary, credential stuffing |
| B (13–20) | Reconnaissance & scanning | Port scan, banner grab, HTTP fingerprint, CGI probe, MQTT topic enum, UPnP probe, APT slow recon |
| C (21–30) | Exploitation attempts | Shellshock, DASAN RCE, Huawei HG532, Realtek SDK, buffer overflow, dir traversal, Log4Shell, Spring4Shell |
| D (31–39) | Post-exploitation | wget dropper, chmod+execute, crontab persistence, iptables manipulation, crypto miner install, C2 callback, self-propagation, log wipe |
| E (40–47) | Timing / anomaly | Hawkes burst A & B, periodic botnet, diurnal night campaign, multi-protocol chain, TLS downgrade, MQTT QoS abuse, zero-day anomaly |

---

## Security Notes

> **Deploy only on isolated or monitored network segments.**

- `include/secrets.h` is gitignored — never commit real credentials
- The firmware deliberately accepts Mirai top-100 credentials to lure attackers into richer command sessions
- InfluxDB and Grafana use open authentication in this dev configuration — enable auth before any internet-facing deployment
- Port 1883 (MQTT) accepts anonymous connections — do not expose it directly to the internet
- GeoIP enrichment stores a SHA-256 hash of source IPs (daily rotating salt) rather than raw addresses in InfluxDB

---

## File Structure

```
├── platformio.ini
├── include/
│   ├── secrets.h.template      ← copy to secrets.h and fill in values
│   ├── event_logger.h
│   ├── wifi_manager.h
│   ├── mqtt_service.h
│   ├── telnet_honeypot.h
│   ├── ssh_honeypot.h
│   ├── http_honeypot.h
│   ├── vuln_matrix.h           ← Mirai top-100 credential matrix
│   └── attack_patterns.h       ← 47-pattern enum + on-device classifier
├── src/
│   ├── main.cpp
│   ├── event_logger.cpp
│   ├── wifi_manager.cpp
│   ├── mqtt_service.cpp
│   ├── telnet_honeypot.cpp
│   ├── ssh_honeypot.cpp
│   └── http_honeypot.cpp
├── backend/
│   ├── docker-compose.yml
│   ├── .env.template
│   ├── mosquitto/mosquitto.conf
│   ├── telegraf/telegraf.conf
│   ├── influxdb/setup.sh
│   ├── classifier/             ← Phase 2 classification microservice
│   │   ├── main.py             ← FastAPI app + 60s scheduler
│   │   ├── patterns.py         ← 47-pattern taxonomy dataclasses
│   │   ├── heuristic_rules.py  ← deterministic rules (groups A–D)
│   │   ├── hawkes_classifier.py← timing analysis (group E, patterns 40–43)
│   │   ├── hmm_classifier.py   ← HMM Viterbi kill-chain sequencing
│   │   ├── anomaly_detector.py ← Z-score + DBSCAN (pattern 47)
│   │   ├── geoip_enricher.py   ← ip-api.com + IP hashing
│   │   └── influx_client.py    ← InfluxDB read/write helpers
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/influxdb.yaml
│       │   ├── dashboards/dashboard.yaml
│       │   └── alerting/       ← alert rules + contact points
│       └── dashboards/
│           ├── honeypot_overview.json   ← Phase 1 dashboard
│           └── honeypot_patterns.json  ← Phase 2 pattern dashboard
└── scripts/
    ├── simulate_attacks.py     ← synthetic event generator (Phase 1 + 2)
    └── check_pipeline.sh       ← health-check all services
```
