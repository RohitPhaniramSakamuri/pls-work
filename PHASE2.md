# Phase 2 — Attack Pattern Identification, Classification & Grafana Monitoring

## Research Basis

This phase implements the attack clustering and classification methodology from:

> **"Using Honeypots to Model Botnet Attacks on the Internet of Medical Things"** (PMC9264116)
> — which processed 128,737 real attack sessions and resolved them into **47 distinct botnet clusters**
> using a Multivariate Hawkes Process model, then refined those into 121 temporal sub-clusters.

Key findings from that paper that drive this implementation:
- Weak password exploitation is the **primary IoT attack surface** (credential brute-force dominates)
- Bots on the same /24 subnet tend to try **identical credential combinations** (e.g. Control4 default `root/t0talc0ntr0l4!`)
- 74% of bots are segmented into fewer than 10 temporal fragments by control period
- Attack timing patterns (inter-arrival rates, burst shapes) are sufficient to fingerprint botnet families

Additional taxonomy from the honeypot literature (Mirai, Mozi, Hajime, HoneyIoT, autoencoder clustering papers) defines the 47 named patterns implemented below.

---

## Objective

Extend the existing honeypot system with:

1. **`backend/classifier/`** — a Python microservice that consumes events from InfluxDB and assigns each session a pattern label from the 47-pattern taxonomy
2. **Updated MQTT event schema** — add `pattern_id`, `pattern_name`, `confidence`, `cluster_id` fields
3. **Updated ESP32 firmware** — lightweight on-device pre-classification (heuristic rules) to tag events before they leave the device
4. **New Grafana dashboard panels** — visualise pattern distribution, cluster timelines, and per-pattern drill-downs

---

## The 47 Attack Pattern Taxonomy

Implement these as named constants in both firmware (`src/attack_patterns.h`) and the classifier service (`backend/classifier/patterns.py`). Each pattern has: an ID, a short name, the protocol(s) it targets, its primary indicator, and the botnet family it maps to.

### Group A — Credential Brute Force (patterns 1–12)

| ID | Name | Protocol | Primary Indicator | Botnet Family |
|----|------|----------|-------------------|---------------|
| 1 | MIRAI_DEFAULT_CREDS | Telnet/SSH | Tries root/xc3511, root/vizxv in first 3 attempts | Mirai |
| 2 | MIRAI_ADMIN_SWEEP | Telnet/SSH | Cycles admin/admin → admin/1234 → admin/password sequentially | Mirai variant |
| 3 | MOZI_ROUTER_CREDS | Telnet/HTTP | Targets `root/root`, `Admin/Admin`, `admin/` on port 23 and 80 simultaneously | Mozi |
| 4 | HAJIME_SLOW_BRUTE | SSH | Low rate (<2 attempts/min), randomised credential order, long session dwell | Hajime |
| 5 | CONTROL4_TARGETED | Telnet | Exclusively tries `root/t0talc0ntr0l4!` — single attempt, moves on | Control4 botnet |
| 6 | GAFGYT_DEFAULT | Telnet | root/888888, root/default in rapid succession (<500ms between) | Gafgyt/Bashlite |
| 7 | SATORI_HUAWEI | Telnet | Tries `root/Zte521`, targets port 37215 probe first | Satori |
| 8 | FBOT_FBXROUTER | HTTP/Telnet | `supervisor/zyad1234`, `telecomadmin/admintelecom` combos | FBot |
| 9 | GENERIC_DICT_FAST | Telnet/SSH | >10 attempts/min, sequential dictionary ordering, no per-IP state | Generic scanner |
| 10 | CREDENTIAL_STUFFING | HTTP | POST /login with base64-encoded JSON bodies, User-Agent rotates | Web credential attack |
| 11 | SINGLE_SHOT_DEFAULT | Any | Exactly 1 attempt per connection, always `admin/admin` or `root/root` | Shodan/Censys probe |
| 12 | SUBNET_COORDINATED | Telnet/SSH | Multiple source IPs in same /24 using identical credential | Coordinated botnet |

### Group B — Reconnaissance & Scanning (patterns 13–20)

| ID | Name | Protocol | Primary Indicator | Family |
|----|------|----------|-------------------|--------|
| 13 | PORT_SCAN_SEQUENTIAL | TCP | Connections to ports 22, 23, 80, 1883, 8080, 8443 within 10s from same IP | Masscan/Zmap |
| 14 | BANNER_GRAB_ONLY | SSH/Telnet | Connects, reads banner, disconnects without sending any data | Shodan crawler |
| 15 | HTTP_FINGERPRINT | HTTP | GET /, HEAD /, GET /favicon.ico in sequence; reads Server header | Web scanner |
| 16 | CGI_PROBE | HTTP | GET requests to /cgi-bin/, /shell, /command, /cmd within single session | CVE scanner |
| 17 | MQTT_TOPIC_ENUM | MQTT | Subscribes to `#` wildcard or `$SYS/#` immediately after CONNECT | MQTT recon |
| 18 | UPnP_PROBE | HTTP | GET /description.xml, GET /rootDesc.xml, port 1900 UDP | UPnP scanner |
| 19 | MITRE_T1046_NETSCAN | TCP | SYN packets across >5 ports, no ACK completion, <100ms between | Network service scan |
| 20 | SLOW_RECON | TCP | One connection every 5–60 min from same IP over 24h; low-and-slow | APT recon |

### Group C — Exploitation Attempts (patterns 21–30)

| ID | Name | Protocol | Primary Indicator | CVE / Family |
|----|------|----------|-------------------|--------------|
| 21 | SHELLSHOCK | HTTP | `() { :;}; /bin/bash` in User-Agent or HTTP headers | CVE-2014-6271 |
| 22 | DASAN_RCE | HTTP | GET /GponForm/diag_Form?images/ with command injection in dest param | CVE-2018-10562 |
| 23 | HUAWEI_HG532_RCE | HTTP | POST /ctrlt/DeviceUpgrade_1 with `NewStatusURL` command injection | CVE-2017-17215 |
| 24 | REALTEK_SDK_RCE | HTTP | POST /soap.cgi with UPnP SUBSCRIBE body containing shell commands | CVE-2021-35395 |
| 25 | BUFFER_OVERFLOW_TELNET | Telnet | Input >256 bytes in single line, often NOP sled + shellcode pattern | Generic BOF |
| 26 | DIR_TRAVERSAL_HTTP | HTTP | `../` sequences in URL path, attempts to read /etc/passwd or /proc/ | Path traversal |
| 27 | COMMAND_INJECTION_HTTP | HTTP | `;`, `|`, `&&`, backtick in form field values or GET params | Generic CMDi |
| 28 | MQTT_MALICIOUS_PUBLISH | MQTT | PUBLISH to `cmnd/` or `zigbee2mqtt/` topics with shell payload in body | MQTT exploitation |
| 29 | LOG4SHELL_PROBE | HTTP | `${jndi:ldap://` in any HTTP header or body field | CVE-2021-44228 |
| 30 | SPRING4SHELL_PROBE | HTTP | POST with `class.module.classLoader` parameter | CVE-2022-22965 |

### Group D — Post-Exploitation Behaviour (patterns 31–39)

| ID | Name | Protocol | Primary Indicator | Family |
|----|------|----------|-------------------|--------|
| 31 | WGET_DROPPER | Telnet/SSH | `wget http://` or `curl http://` executed post-auth | Mirai/Mozi dropper |
| 32 | BUSYBOX_WGET_CHAIN | Telnet | `/bin/busybox wget` + `/bin/busybox SATORI` or `/bin/busybox ECCHI` | Satori/Ecchi |
| 33 | CHMOD_EXECUTE | Telnet/SSH | `chmod +x` followed immediately by `./` execution of downloaded file | Generic dropper |
| 34 | CRONTAB_PERSISTENCE | Telnet/SSH | `crontab -e` or `echo ... >> /etc/cron` — persistence attempt | APT persistence |
| 35 | IPTABLES_MANIPULATION | Telnet/SSH | `iptables -F` (flush) or `iptables -A` adding rules | Botnet firewall bypass |
| 36 | CRYPTO_MINER_INSTALL | Telnet/SSH | Download of `xmrig`, `minerd`, or references to mining pool URLs | Cryptojacker |
| 37 | C2_CALLBACK_ATTEMPT | Telnet/SSH | `nc`, `ncat`, or `bash -i >& /dev/tcp/` reverse shell commands | C2 establishment |
| 38 | SELF_PROPAGATION | Telnet/SSH | `for i in` loop scanning subnet, attempting login to other IPs | Self-replicating worm |
| 39 | LOG_WIPE | Telnet/SSH | `rm /var/log/`, `echo > /var/log/messages`, `history -c` | Anti-forensics |

### Group E — Protocol-Specific & Timing Patterns (patterns 40–47)

| ID | Name | Protocol | Primary Indicator | Notes |
|----|------|----------|-------------------|-------|
| 40 | HAWKES_BURST_A | Any | High-intensity burst (>20 events/min) followed by silence >30 min | Hawkes cluster type A |
| 41 | HAWKES_BURST_B | Any | Moderate sustained rate (5–15/min) over >2 hours | Hawkes cluster type B |
| 42 | HAWKES_PERIODIC | Any | Regular inter-arrival time with low variance (CV < 0.3) | Scheduled botnet job |
| 43 | DIURNAL_NIGHT | Any | Attacks concentrate between 00:00–06:00 UTC | Night-time campaign |
| 44 | MULTI_PROTOCOL_CHAIN | Multiple | Same source IP hits Telnet + HTTP + MQTT within 60s | Multi-vector probe |
| 45 | TLS_DOWNGRADE | SSH/HTTPS | Attempts SSLv3/TLS1.0 after TLS1.3 rejection | TLS downgrade attack |
| 46 | MQTT_QOS_ABUSE | MQTT | Publishes QoS 2 messages rapidly to exhaust broker state | MQTT DoS |
| 47 | ZERO_DAY_ANOMALY | Any | Anomaly score > threshold; does not match patterns 1–46 | Unknown/novel |

---

## Implementation Spec

### 1. Firmware — `src/attack_patterns.h`

Define the full enum and a lightweight heuristic matcher that runs on-device:

```cpp
enum AttackPattern {
    PATTERN_UNKNOWN = 0,
    PATTERN_MIRAI_DEFAULT_CREDS = 1,
    // ... through 47
    PATTERN_ZERO_DAY_ANOMALY = 47
};

// Per-session state for heuristic matching
struct SessionContext {
    uint8_t auth_attempt_count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char last_user[32];
    char last_pass[32];
    char last_cmd[128];
    bool downloaded_file;
    bool executed_file;
    bool chmod_seen;
};

// Returns best-match pattern ID (0 if unknown)
AttackPattern classify_session(const SessionContext& ctx);
```

The on-device classifier only needs to cover Groups A, B, and D (credential + post-exploit) — the Hawkes timing patterns (Group E) require multi-session data and run only in the backend classifier.

### 2. Updated Event JSON Schema

Add these fields to every event published to MQTT:

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

`session_id` is a 6-char hex identifier shared across all events from the same TCP connection. `confidence` is 0.0–1.0 (on-device heuristics emit 0.7 max; backend classifier can revise upward to 1.0).

### 3. Backend Classifier Service — `backend/classifier/`

A standalone Python service (FastAPI + APScheduler) that:
- Polls InfluxDB every 60 seconds for uncategorised sessions
- Applies the full 47-pattern ruleset including Hawkes timing analysis
- Writes `pattern_id`, `pattern_name`, `confidence` back to InfluxDB as tag + field updates
- Exposes `GET /patterns/summary` — JSON count of each pattern in last 24h
- Exposes `GET /patterns/{id}` — last 50 sessions matching that pattern

**File tree:**
```
backend/classifier/
├── Dockerfile
├── requirements.txt          # influxdb-client, fastapi, uvicorn, apscheduler, numpy, scipy
├── main.py                   # FastAPI app + scheduler startup
├── patterns.py               # 47-pattern taxonomy as dataclasses
├── heuristic_rules.py        # Rules for groups A–D (deterministic)
├── hawkes_classifier.py      # Hawkes process inter-arrival timing (group E)
├── anomaly_detector.py       # Z-score + DBSCAN for pattern 47
└── influx_client.py          # InfluxDB read/write helpers
```

**`patterns.py` structure:**
```python
from dataclasses import dataclass
from enum import IntEnum

class PatternID(IntEnum):
    UNKNOWN = 0
    MIRAI_DEFAULT_CREDS = 1
    # ... all 47

@dataclass
class AttackPattern:
    id: PatternID
    name: str
    group: str          # A/B/C/D/E
    protocols: list[str]
    primary_indicator: str
    botnet_family: str
    mitre_technique: str   # e.g. "T1110.001" for credential brute-force

PATTERNS: dict[int, AttackPattern] = { ... }  # fully populated for all 47
```

**`heuristic_rules.py`** — implement these as pure functions over a session dict:
- `match_credential_patterns(session)` → checks credential combos against known lists per pattern 1–12
- `match_recon_patterns(session)` → checks connection sequence, timing, path patterns 13–20
- `match_exploit_patterns(session)` → regex matches against payload/path/header content, patterns 21–30
- `match_postexploit_patterns(session)` → command sequence analysis, patterns 31–39

**`hawkes_classifier.py`** — simplified Hawkes intensity:
- Compute inter-arrival times for all events from a given src_ip over a rolling 2-hour window
- Calculate coefficient of variation (CV) of inter-arrival times
- Compute burst score: ratio of max 5-min event rate to mean rate
- Map (CV, burst_score) to patterns 40–43 using threshold grid

**`anomaly_detector.py`** — pattern 47 (ZERO_DAY_ANOMALY):
- Feature vector: [attempt_count, unique_paths, payload_entropy, session_duration, protocol_switches]
- Fit Z-score baseline from last 7 days of data
- If any feature > 3σ from baseline AND no pattern 1–46 matched → assign pattern 47
- Log the feature vector for manual review

Add the classifier service to `docker-compose.yml`:
```yaml
classifier:
  build: ./classifier
  depends_on:
    - influxdb
  environment:
    - INFLUX_URL=http://influxdb:8086
    - INFLUX_TOKEN=${INFLUX_TOKEN}
    - INFLUX_ORG=honeypot
    - INFLUX_BUCKET=attacks
  ports:
    - "8000:8000"
  restart: unless-stopped
```

---

## Grafana Dashboard Additions

Add these panels to a new dashboard `honeypot_patterns.json` (do not modify the existing `honeypot_overview.json`):

### Panel 1 — Pattern Distribution Heatmap
- Type: **heatmap**
- X-axis: time (1h buckets)
- Y-axis: pattern_name (all 47, sorted by group A→E)
- Color: event count (log scale)
- Query: `from(bucket:"attacks") |> range(start: -7d) |> filter(fn: (r) => r._field == "pattern_id") |> group(columns: ["pattern_name", "_time"]) |> count()`

### Panel 2 — Top 10 Active Patterns (stat grid)
- Type: **stat** (10 tiles in 2×5 grid)
- Each tile: pattern name + count + colored by group (A=red, B=orange, C=yellow, D=purple, E=blue)
- Time range: last 24h

### Panel 3 — Attack Kill Chain Timeline
- Type: **timeline** (Grafana state timeline)
- Rows: one per active `session_id` (last 50 active sessions)
- States: RECON → AUTH_ATTEMPT → AUTH_SUCCESS → EXPLOIT → POST_EXPLOIT
- Color: maps to group A/B/C/D/E
- Shows multi-stage progression per attacker

### Panel 4 — Pattern Confidence Distribution
- Type: **histogram**
- Field: `confidence`
- Bucket size: 0.05
- Color by: pattern_group
- Shows whether on-device vs backend classifier is doing the work

### Panel 5 — Botnet Family Attribution (pie chart)
- Groups events by `botnet_family` tag
- Families: Mirai, Mozi, Hajime, Gafgyt, Satori, FBot, Cryptojacker, APT, Unknown
- Time: last 48h

### Panel 6 — MITRE ATT&CK Coverage (bar chart)
- X-axis: MITRE technique IDs (T1046, T1110.001, T1059, T1136, etc.)
- Y-axis: event count
- One bar per technique observed, last 7d
- Link each bar to MITRE ATT&CK URL via data link

### Panel 7 — Zero-Day Anomaly Feed (logs panel)
- Filters: `pattern_id == 47`
- Columns: timestamp, src_ip, proto, session_duration_ms, anomaly feature vector (JSON)
- Sorted: newest first
- Alert rule: if count > 0 in last 10 min → fire webhook

### Panel 8 — Subnet Coordination Detector (table)
- Shows /24 subnets where >3 distinct IPs used identical credentials within 1 hour
- Columns: subnet, distinct_ips, credential_used, first_seen, last_seen, pattern
- Highlights coordinated botnet campaigns (pattern 12)

### Panel 9 — Attack Velocity Sparklines
- 9 small sparklines, one per botnet family
- Each shows events/hour over last 24h
- Allows rapid visual comparison of campaign intensity

### Panel 10 — Session Kill Chain Sankey
- Type: **Sankey** (use Grafana plugin `volkovlabs-echarts-panel`)
- Flow: source_country → protocol → pattern_group → outcome (captured/dropped)
- Width of flow proportional to event count

---

## Updated Simulation Script

Update `scripts/simulate_attacks.py` to emit events for all 47 patterns, not just generic attacks:

```
python scripts/simulate_attacks.py \
  --broker localhost \
  --port 1883 \
  --patterns all \        # or comma-separated IDs e.g. "1,12,31,47"
  --sessions 200 \        # total sessions to simulate
  --duration 300          # spread over 300 seconds
```

Each simulated session must set `pattern_id`, `pattern_name`, `confidence`, and `session_id` correctly so the Grafana dashboards populate immediately without needing real attack traffic.

---

## Validation Criteria

All of the following must pass before the session ends:

```bash
# 1. Classifier service is healthy
curl -s http://localhost:8000/patterns/summary | python3 -m json.tool | grep -c "pattern"

# 2. All 47 patterns are registered
curl -s http://localhost:8000/patterns/summary | python3 -c \
  "import sys,json; d=json.load(sys.stdin); assert len(d)==47, f'Only {len(d)} patterns'"

# 3. Simulate one session per pattern group and verify InfluxDB tagging
python scripts/simulate_attacks.py --patterns all --sessions 50 --duration 30
sleep 10
curl -s "http://localhost:8086/api/v2/query?org=honeypot" \
  -H "Authorization: Token $INFLUX_TOKEN" \
  -H "Content-Type: application/vnd.flux" \
  --data 'from(bucket:"attacks") |> range(start:-5m) |> filter(fn:(r) => r["pattern_name"] != "") |> count()' \
  | grep -c "_value"

# 4. Firmware compiles with attack_patterns.h included
pio run

# 5. New Grafana dashboard exists and has 10 panels
curl -s -u admin:admin http://localhost:3000/api/dashboards/db/honeypot-patterns \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['dashboard']['panels'])==10"
```

---

## File Tree Delta (additions only)

```
src/
└── attack_patterns.h           ← new: 47-pattern enum + on-device classifier

backend/
├── classifier/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── patterns.py
│   ├── heuristic_rules.py
│   ├── hawkes_classifier.py
│   ├── anomaly_detector.py
│   └── influx_client.py
└── grafana/
    └── dashboards/
        └── honeypot_patterns.json   ← new: 10-panel patterns dashboard

scripts/
└── simulate_attacks.py              ← updated: all 47 patterns
```

---

## Claude Code Behaviour Notes

- Build `patterns.py` and `heuristic_rules.py` first — everything else depends on the taxonomy being correct
- Implement all 47 patterns with real logic; do not stub them with `pass` or `return UNKNOWN`
- The Hawkes classifier can use a simplified threshold-based approximation (no full MLE fitting needed on this hardware) — CV and burst ratio are sufficient
- For the Grafana Sankey panel, if the ECharts plugin is not pre-installed, fall back to a **node graph** panel which is built-in — document the substitution in a comment
- Run `pio run` after modifying `attack_patterns.h` before moving to backend work
- Do not modify `honeypot_overview.json` — only add `honeypot_patterns.json`
- Only interrupt the user if the InfluxDB token from Phase 1 is not in the `.env` file