# ESP32 IoT Honeypot — Claude Code Autonomous Build Guide

## Project Overview

Build a full distributed IoT honeypot system on ESP32 (PlatformIO), with a real-time analytics backend and Grafana dashboard. All three tiers must be functional at the end of the session:

1. **Embedded Honeypot Layer** — ESP32 firmware (PlatformIO / Arduino framework)
2. **Data Aggregation Pipeline** — MQTT broker + InfluxDB + stream processor (Docker Compose, runs on the host machine)
3. **Analytics & Visualization Dashboard** — Grafana with pre-provisioned dashboards

---

## Assumptions / Starting State

- PlatformIO CLI is installed and on PATH (`pio` command works)
- A `platformio.ini` already exists (bare basics scaffold)
- Docker and Docker Compose are available on the host
- Python 3.10+ available on host for any helper scripts
- Target board: **ESP32 DevKit v1** (change `board` in `platformio.ini` if different)
- The ESP32 will connect to a Wi-Fi network; credentials go in `include/secrets.h` (gitignored)

---

## Deliverables Checklist

Claude Code must produce ALL of the following before ending the session:

### Firmware (`firmware/`)
- [ ] `src/main.cpp` — entry point, initialises all services
- [ ] `src/wifi_manager.cpp/.h` — Wi-Fi connection + reconnect loop
- [ ] `src/telnet_service.cpp/.h` — Telnet honeypot (port 23), BusyBox shell emulation
- [ ] `src/ssh_emulator.cpp/.h` — SSH-2.0 banner + weak handshake capture (port 22 via raw TCP)
- [ ] `src/http_service.cpp/.h` — HTTP management portal honeypot (port 80)
- [ ] `src/mqtt_service.cpp/.h` — MQTT honeypot listener (port 1883)
- [ ] `src/event_logger.cpp/.h` — hierarchical event logger, Protobuf serialisation, batched MQTT publish
- [ ] `src/vuln_matrix.h` — credential list (Mirai top-100), weak cipher config constants
- [ ] `include/secrets.h.template` — template for Wi-Fi + backend MQTT broker credentials (never commit real values)
- [ ] `platformio.ini` — updated with all required libraries

### Backend (`backend/`)
- [ ] `docker-compose.yml` — InfluxDB 2.x, Mosquitto MQTT broker, Telegraf, Grafana
- [ ] `mosquitto/mosquitto.conf` — allow anonymous, persistence enabled
- [ ] `telegraf/telegraf.conf` — subscribe to honeypot MQTT topics, write to InfluxDB
- [ ] `influxdb/setup.sh` — initialise org, bucket, token
- [ ] `grafana/provisioning/datasources/influxdb.yaml`
- [ ] `grafana/provisioning/dashboards/dashboard.yaml`
- [ ] `grafana/dashboards/honeypot_overview.json` — pre-built dashboard (see Dashboard Spec below)

### Scripts (`scripts/`)
- [ ] `scripts/simulate_attacks.py` — sends synthetic attack events to test the full pipeline end-to-end without real hardware
- [ ] `scripts/check_pipeline.sh` — health-check script that verifies all Docker services are up and data flows through

### Documentation
- [ ] `README.md` — quick-start, wiring, flash instructions, how to run backend

---

## Architecture Details

### Network Topology

```
[Internet / LAN attackers]
         |
    [ESP32 Honeypot]  ← runs all 4 protocol services concurrently
         |  (publishes events via MQTT over Wi-Fi)
    [MQTT Broker - Mosquitto]  ← host machine, Docker
         |
    [Telegraf]  ← subscribes, parses, enriches
         |
    [InfluxDB 2.x]  ← time-series storage
         |
    [Grafana]  ← dashboards, alerts
```

### MQTT Topic Schema (ESP32 → Broker)

```
honeypot/events/auth        — authentication attempts
honeypot/events/connect     — new TCP connections
honeypot/events/command     — post-auth command execution
honeypot/events/exploit     — detected exploit attempt
honeypot/events/heartbeat   — 30-second system stats
```

Payload format — JSON (compact, fits ESP32 constraints):
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

---

## Firmware Implementation Spec

### `platformio.ini` — Required Libraries

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps =
    knolleary/PubSubClient @ ^2.8
    bblanchon/ArduinoJson @ ^7.0
    esphome/AsyncTCP-esphome @ ^2.1
    me-no-dev/ESP Async WebServer @ ^1.2.4
    nanopb/Nanopb @ ^0.4.8
build_flags =
    -DCORE_DEBUG_LEVEL=3
    -DCONFIG_ASYNC_TCP_MAX_ACK_TIME=5000
```

### Memory Budget (520 KB SRAM)

| Component | Allocation |
|---|---|
| Telnet sessions (max 5) | 10 KB |
| HTTP request buffer | 8 KB |
| MQTT client + buffer | 6 KB |
| SSH buffer | 4 KB |
| Event queue | 8 KB |
| Stack + heap overhead | ~40 KB |
| **Total target** | **< 76 KB dynamic** |

Use static allocation where possible. Use `AsyncTCP` for non-blocking I/O to handle concurrent connections without stack-per-task overhead.

### Telnet Service — BusyBox Emulation

Bind to port 23 with `AsyncServer`. On connect, send:
```
\r\nBusyBox v1.29.3 (2019-01-24 15:05:49 UTC) built-in shell (ash)\r\n\r\n/ # 
```

Respond to these commands with realistic output:
- `uname -a` → `Linux DVR 3.10.0 #1 SMP PREEMPT armv7l GNU/Linux`
- `cat /etc/passwd` → truncated passwd with root entry
- `ls`, `id`, `whoami`, `wget`, `curl`, `cat /proc/cpuinfo` — all simulated
- Any unknown command → `sh: command not found`

Log ALL input lines as `command` events.

### Credential Matrix — `vuln_matrix.h`

Hardcode the Mirai top-100 credential pairs as a `const char* MIRAI_CREDS[][2]` array.

Mirai top credentials include (but are not limited to):
`root/xc3511`, `root/vizxv`, `admin/admin`, `root/888888`, `root/default`, `root/root`, `admin/`, `root/`, `root/12345`, `admin/1234`, `user/user`, `admin/password`, `root/pass`, `root/1234`, etc.

Include all 100 pairs. Always accept these credentials as "valid" so attackers escalate to shell — this triggers richer command logging.

### HTTP Service

Serve on port 80 via `ESPAsyncWebServer`. Routes:

| Path | Response |
|---|---|
| `GET /` | Redirect to `/login` |
| `GET /login` | HTML login form (camera/NAS theme) |
| `POST /login` | Log credentials, return "Invalid password" unless Mirai cred — then redirect to `/admin` |
| `GET /admin` | Fake admin panel HTML |
| `GET /cgi-bin/` | 200 OK with empty body (triggers exploit scanners) |
| `GET /../../../etc/passwd` | Log directory traversal, return 404 |
| Any other path | 404, log the attempted path |

### SSH Emulator

Raw TCP on port 22. On connect, send SSH identification string:
```
SSH-2.0-OpenSSH_7.4\r\n
```

Accept the TCP stream, read up to 512 bytes, log the SSH client banner and any key exchange init bytes as a `connect` event. Do not implement full SSH — this is a low-interaction capture of the banner exchange and scanning activity.

### MQTT Honeypot Listener

Use a second `AsyncServer` on port 1883. Accept raw TCP connections. Parse the first CONNECT packet (fixed header `0x10`), extract client ID, username, password from the packet bytes. Log as `auth_attempt`. Send a CONNACK with return code 0x00 (accepted) to lure further packets. Log any PUBLISH packets (topic + payload) as `command` events.

### Event Logger

```cpp
struct HoneypotEvent {
    uint32_t timestamp;
    char proto[8];
    char src_ip[16];
    char username[32];
    char password[32];
    char command[128];
    char event_type[24];
};
```

- Queue events in a circular buffer (max 50 events)
- Every 30 seconds: flush queue to JSON array, publish to `honeypot/events/heartbeat` and appropriate topic
- Immediate publish for: successful auth (`auth_success`), command execution, exploit detection
- Implement exponential backoff (1s → 2s → 4s → max 30s) on MQTT publish failure

---

## Backend Implementation Spec

### `docker-compose.yml`

Services:
- **mosquitto** — `eclipse-mosquitto:2.0`, ports `1883:1883`, `9001:9001` (WebSocket)
- **influxdb** — `influxdb:2.7`, port `8086:8086`, persistent volume
- **telegraf** — `telegraf:1.30`, depends on influxdb + mosquitto
- **grafana** — `grafana/grafana:10.4.0`, port `3000:3000`, depends on influxdb

All services on a shared `honeypot_net` bridge network.

### Telegraf Config

```toml
[[inputs.mqtt_consumer]]
  servers = ["tcp://mosquitto:1883"]
  topics = ["honeypot/events/#"]
  data_format = "json"
  json_time_key = "ts"
  json_time_format = "unix"

[[outputs.influxdb_v2]]
  urls = ["http://influxdb:8086"]
  token = "$INFLUX_TOKEN"
  organization = "honeypot"
  bucket = "attacks"
```

### InfluxDB Setup

Create org `honeypot`, bucket `attacks`, retention 365d. Generate an operator token and write it to a `.env` file that Docker Compose reads. The `influxdb/setup.sh` should be idempotent (check if org exists before creating).

---

## Dashboard Spec — `honeypot_overview.json`

Build a Grafana dashboard JSON with these panels:

1. **Attack Rate (time series)** — events/minute over last 24h, threshold line at 60/min
2. **Protocol Breakdown (pie chart)** — events grouped by `proto` field, last 6h
3. **Top Source IPs (table)** — top 20 attacker IPs by event count, last 24h
4. **Top Credential Pairs (table)** — username + password, count, last 24h
5. **Attack Type Distribution (bar chart)** — event_type counts, last 6h
6. **Commands Executed (logs panel)** — last 50 `command` events with timestamp, src_ip, command
7. **Active Attackers (stat)** — unique src_ip count, last 1h
8. **Total Events (stat)** — total event count since deployment
9. **System Heartbeat (table)** — last 5 heartbeats from ESP32 nodes with free heap

Dashboard variables:
- `$node` — multi-select from distinct `node` tag values
- `$proto` — filter by protocol

Refresh: 10s auto-refresh.

---

## Simulation Script — `scripts/simulate_attacks.py`

This script lets you test the full pipeline WITHOUT real hardware. It publishes synthetic events to the MQTT broker covering all attack types and verifies Grafana receives data.

Must simulate:
- 50 auth attempts with randomised IPs and Mirai credential pairs
- 10 successful auths followed by command sequences
- 5 directory traversal HTTP attempts
- 3 SSH banner grabs
- 2 MQTT unauthorised publish attempts
- Continuous heartbeats every 30s for 2 minutes

Usage: `python scripts/simulate_attacks.py --broker localhost --port 1883`

---

## Validation Criteria (must all pass before session ends)

Run these checks and fix until they pass:

```bash
# 1. Firmware compiles cleanly
pio run

# 2. All Docker services healthy
docker compose -f backend/docker-compose.yml up -d
docker compose -f backend/docker-compose.yml ps   # all should be "healthy" or "running"

# 3. Pipeline smoke test
python scripts/simulate_attacks.py --broker localhost --port 1883 --count 20

# 4. InfluxDB has data
curl -s "http://localhost:8086/api/v2/query?org=honeypot" \
  -H "Authorization: Token $INFLUX_TOKEN" \
  -H "Content-Type: application/vnd.flux" \
  --data 'from(bucket:"attacks") |> range(start: -1h) |> count()' | grep -c "_value"

# 5. Grafana is accessible
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health | grep 200
```

The session is complete only when ALL five checks return success.

---

## Security Notes (do NOT skip)

- `include/secrets.h` is gitignored — never commit real credentials
- Mirai credential pairs are well-known public data (published in academic literature and CVE databases) — inclusion is for honeypot fidelity only
- The honeypot firmware deliberately accepts Mirai creds — only deploy on isolated/monitored network segments
- InfluxDB and Grafana should have authentication enabled in production — the Docker Compose defaults to open for dev convenience; document this warning in README

---

## File Tree (target state)

```
.
├── CLAUDE.md                          ← this file
├── README.md
├── platformio.ini
├── include/
│   └── secrets.h.template
├── src/
│   ├── main.cpp
│   ├── wifi_manager.cpp / .h
│   ├── telnet_service.cpp / .h
│   ├── ssh_emulator.cpp / .h
│   ├── http_service.cpp / .h
│   ├── mqtt_service.cpp / .h
│   ├── event_logger.cpp / .h
│   └── vuln_matrix.h
├── backend/
│   ├── docker-compose.yml
│   ├── .env.template
│   ├── mosquitto/
│   │   └── mosquitto.conf
│   ├── telegraf/
│   │   └── telegraf.conf
│   ├── influxdb/
│   │   └── setup.sh
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/influxdb.yaml
│       │   └── dashboards/dashboard.yaml
│       └── dashboards/
│           └── honeypot_overview.json
└── scripts/
    ├── simulate_attacks.py
    └── check_pipeline.sh
```

---

## Claude Code Behaviour Notes

- Work through the file tree top-to-bottom, completing each file fully before moving on
- After writing all firmware files, run `pio run` and fix any compilation errors before proceeding to backend
- After standing up Docker Compose, wait for health checks to pass before running the simulation script
- If a library version causes a compile error, try the next semver up/down and update `platformio.ini` accordingly
- Do NOT ask for confirmation between steps — proceed autonomously through the entire build
- Only interrupt the user if: (a) `secrets.h` values are needed (Wi-Fi SSID/password, broker IP), or (b) a hardware-specific board variant needs to be confirmed
- At session end, print the five validation check commands and their results

WIFI CREDENTIALS:
WIFI (hotspot) name: 'ZONGLE'
Password: '12345678'