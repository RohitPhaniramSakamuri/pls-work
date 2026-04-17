# ESP32 IoT Honeypot

A distributed IoT honeypot system that runs on an ESP32, captures attacker activity across four protocols (Telnet, SSH, HTTP, MQTT), and streams events to a real-time analytics pipeline (MQTT → Telegraf → InfluxDB → Grafana).

---

## Architecture

```
[LAN attackers]
      |
 [ESP32 Honeypot]  — Telnet :23 | SSH :22 | HTTP :80 | MQTT :1883
      | publishes JSON events via MQTT
 [Mosquitto broker]  — host machine, Docker
      |
 [Telegraf]  — subscribes, parses, enriches
      |
 [InfluxDB 2.x]  — time-series storage
      |
 [Grafana :3000]  — dashboards, alerts
```

---

## Quick Start

### 1. Hardware

- ESP32 DevKit v1 (or compatible)
- USB cable for flashing
- Host machine on the same LAN (to run Docker)

### 2. Flash the Firmware

```bash
# Install dependencies (once)
pip install platformio

# Clone / open project
cd /path/to/honeypot

# Fill in your secrets
cp include/secrets.h.template include/secrets.h
# Edit include/secrets.h with your Wi-Fi SSID, password, and broker IP

# Build & flash
pio run --target upload

# Monitor serial output
pio device monitor
```

### 3. Start the Backend

```bash
cd backend

# Copy and edit the .env if needed
cp .env.template .env

# Start all services
docker compose up -d

# Wait for health checks (~60 seconds)
docker compose ps
```

Services exposed:
| Service | Port | URL |
|---|---|---|
| Mosquitto MQTT | 1883 | `mqtt://localhost:1883` |
| Mosquitto WS | 9001 | `ws://localhost:9001` |
| InfluxDB | 8086 | `http://localhost:8086` |
| Grafana | 3000 | `http://localhost:3000` |

Grafana default credentials: `admin` / `admin`

### 4. Test Without Hardware

```bash
pip install paho-mqtt

# Run simulation (sends ~100 synthetic attack events)
python scripts/simulate_attacks.py --broker localhost --port 1883

# Or a quick smoke test
python scripts/simulate_attacks.py --broker localhost --port 1883 --count 20
```

### 5. Verify Pipeline

```bash
bash scripts/check_pipeline.sh
```

---

## MQTT Topic Schema

| Topic | Description |
|---|---|
| `honeypot/events/auth` | Auth attempts and successes |
| `honeypot/events/connect` | New TCP connections |
| `honeypot/events/command` | Post-auth command execution |
| `honeypot/events/exploit` | Detected exploit attempts |
| `honeypot/events/heartbeat` | 30-second system stats from ESP32 |

Payload (compact JSON):
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

## Grafana Dashboard

The pre-provisioned **Honeypot Overview** dashboard includes:
1. Attack Rate time series (last 24h)
2. Protocol Breakdown pie chart (last 6h)
3. Top Source IPs table (top 20, last 24h)
4. Top Credential Pairs table (last 24h)
5. Attack Type Distribution bar chart
6. Commands Executed log panel (last 50)
7. Active Attackers stat (last 1h)
8. Total Events stat
9. System Heartbeat table

Dashboard variables: `$node` (multi-select), `$proto` (filter). Auto-refreshes every 10s.

---

## Security Notes

> **WARNING**: Deploy only on isolated / monitored network segments.

- `include/secrets.h` is gitignored — **never commit real credentials**
- The firmware deliberately accepts Mirai credential pairs to lure attackers into richer command sessions
- InfluxDB and Grafana use open authentication in this dev configuration — **enable auth before any internet-facing deployment**
- The honeypot accepts anonymous connections — do not expose port 1883 to the public internet directly

---

## File Structure

```
├── platformio.ini
├── include/
│   ├── secrets.h.template      ← copy to secrets.h, fill in values
│   ├── event_logger.h
│   ├── wifi_manager.h
│   ├── mqtt_service.h
│   ├── telnet_honeypot.h
│   ├── ssh_honeypot.h
│   ├── http_honeypot.h
│   └── vuln_matrix.h           ← Mirai top-100 credential matrix
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
│   └── grafana/
│       ├── provisioning/datasources/influxdb.yaml
│       ├── provisioning/dashboards/dashboard.yaml
│       └── dashboards/honeypot_overview.json
└── scripts/
    ├── simulate_attacks.py
    └── check_pipeline.sh
```
