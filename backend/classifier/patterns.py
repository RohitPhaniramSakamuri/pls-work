"""
patterns.py — 47-pattern attack taxonomy for the ESP32 IoT Honeypot.
Mirrors the firmware attack_patterns.h enum.
"""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List


class PatternID(IntEnum):
    UNKNOWN                  = 0
    MIRAI_DEFAULT_CREDS      = 1
    MIRAI_ADMIN_SWEEP        = 2
    MOZI_ROUTER_CREDS        = 3
    HAJIME_SLOW_BRUTE        = 4
    CONTROL4_TARGETED        = 5
    GAFGYT_DEFAULT           = 6
    SATORI_HUAWEI            = 7
    FBOT_FBXROUTER           = 8
    GENERIC_DICT_FAST        = 9
    CREDENTIAL_STUFFING      = 10
    SINGLE_SHOT_DEFAULT      = 11
    SUBNET_COORDINATED       = 12
    PORT_SCAN_SEQUENTIAL     = 13
    BANNER_GRAB_ONLY         = 14
    HTTP_FINGERPRINT         = 15
    CGI_PROBE                = 16
    MQTT_TOPIC_ENUM          = 17
    UPNP_PROBE               = 18
    MITRE_T1046_NETSCAN      = 19
    SLOW_RECON               = 20
    SHELLSHOCK               = 21
    DASAN_RCE                = 22
    HUAWEI_HG532_RCE         = 23
    REALTEK_SDK_RCE          = 24
    BUFFER_OVERFLOW_TELNET   = 25
    DIR_TRAVERSAL_HTTP       = 26
    COMMAND_INJECTION_HTTP   = 27
    MQTT_MALICIOUS_PUBLISH   = 28
    LOG4SHELL_PROBE          = 29
    SPRING4SHELL_PROBE       = 30
    WGET_DROPPER             = 31
    BUSYBOX_WGET_CHAIN       = 32
    CHMOD_EXECUTE            = 33
    CRONTAB_PERSISTENCE      = 34
    IPTABLES_MANIPULATION    = 35
    CRYPTO_MINER_INSTALL     = 36
    C2_CALLBACK_ATTEMPT      = 37
    SELF_PROPAGATION         = 38
    LOG_WIPE                 = 39
    HAWKES_BURST_A           = 40
    HAWKES_BURST_B           = 41
    HAWKES_PERIODIC          = 42
    DIURNAL_NIGHT            = 43
    MULTI_PROTOCOL_CHAIN     = 44
    TLS_DOWNGRADE            = 45
    MQTT_QOS_ABUSE           = 46
    ZERO_DAY_ANOMALY         = 47


@dataclass
class AttackPattern:
    id: PatternID
    name: str
    group: str           # A/B/C/D/E
    protocols: List[str]
    primary_indicator: str
    botnet_family: str
    mitre_technique: str


PATTERNS: dict[int, AttackPattern] = {
    # ── Group A — Credential Brute Force ──────────────────────────────────────
    1:  AttackPattern(PatternID.MIRAI_DEFAULT_CREDS,     "MIRAI_DEFAULT_CREDS",     "A", ["telnet","ssh"],    "root/xc3511 or root/vizxv in first 3 attempts",                    "Mirai",       "T1110.001"),
    2:  AttackPattern(PatternID.MIRAI_ADMIN_SWEEP,       "MIRAI_ADMIN_SWEEP",       "A", ["telnet","ssh"],    "admin/admin → admin/1234 → admin/password sequential",             "Mirai",       "T1110.001"),
    3:  AttackPattern(PatternID.MOZI_ROUTER_CREDS,       "MOZI_ROUTER_CREDS",       "A", ["telnet","http"],   "root/root, Admin/Admin on port 23 and 80 simultaneously",          "Mozi",        "T1110.001"),
    4:  AttackPattern(PatternID.HAJIME_SLOW_BRUTE,       "HAJIME_SLOW_BRUTE",       "A", ["ssh"],             "<2 attempts/min, randomised credential order, long dwell",         "Hajime",      "T1110.001"),
    5:  AttackPattern(PatternID.CONTROL4_TARGETED,       "CONTROL4_TARGETED",       "A", ["telnet"],          "exclusively root/t0talc0ntr0l4! single attempt",                   "Control4",    "T1110.001"),
    6:  AttackPattern(PatternID.GAFGYT_DEFAULT,          "GAFGYT_DEFAULT",          "A", ["telnet"],          "root/888888 or root/default <500ms between attempts",              "Gafgyt",      "T1110.001"),
    7:  AttackPattern(PatternID.SATORI_HUAWEI,           "SATORI_HUAWEI",           "A", ["telnet"],          "root/Zte521, targets port 37215 first",                            "Satori",      "T1110.001"),
    8:  AttackPattern(PatternID.FBOT_FBXROUTER,          "FBOT_FBXROUTER",          "A", ["http","telnet"],   "supervisor/zyad1234 or telecomadmin/admintelecom",                 "FBot",        "T1110.001"),
    9:  AttackPattern(PatternID.GENERIC_DICT_FAST,       "GENERIC_DICT_FAST",       "A", ["telnet","ssh"],    ">10 attempts/min, sequential dictionary ordering",                 "Generic",     "T1110.001"),
    10: AttackPattern(PatternID.CREDENTIAL_STUFFING,     "CREDENTIAL_STUFFING",     "A", ["http"],            "POST /login with base64 JSON bodies, rotating User-Agent",         "Generic",     "T1110.001"),
    11: AttackPattern(PatternID.SINGLE_SHOT_DEFAULT,     "SINGLE_SHOT_DEFAULT",     "A", ["telnet","ssh","http"], "exactly 1 attempt per connection, admin/admin or root/root",   "Generic",     "T1110.001"),
    12: AttackPattern(PatternID.SUBNET_COORDINATED,      "SUBNET_COORDINATED",      "A", ["telnet","ssh"],    "multiple /24 IPs using identical credentials",                     "Coordinated", "T1110.001"),
    # ── Group B — Reconnaissance & Scanning ──────────────────────────────────
    13: AttackPattern(PatternID.PORT_SCAN_SEQUENTIAL,    "PORT_SCAN_SEQUENTIAL",    "B", ["tcp"],             "ports 22,23,80,1883 within 10s from same IP",                     "Masscan",     "T1046"),
    14: AttackPattern(PatternID.BANNER_GRAB_ONLY,        "BANNER_GRAB_ONLY",        "B", ["ssh","telnet"],    "connect, read banner, disconnect with no data sent",               "Shodan",      "T1046"),
    15: AttackPattern(PatternID.HTTP_FINGERPRINT,        "HTTP_FINGERPRINT",        "B", ["http"],            "GET /, HEAD /, GET /favicon.ico; reads Server header",             "Generic",     "T1046"),
    16: AttackPattern(PatternID.CGI_PROBE,               "CGI_PROBE",               "B", ["http"],            "/cgi-bin/, /shell, /command, /cmd within single session",          "Generic",     "T1203"),
    17: AttackPattern(PatternID.MQTT_TOPIC_ENUM,         "MQTT_TOPIC_ENUM",         "B", ["mqtt"],            "subscribes to # or $SYS/# immediately after CONNECT",             "Generic",     "T1046"),
    18: AttackPattern(PatternID.UPNP_PROBE,              "UPNP_PROBE",              "B", ["http"],            "GET /description.xml or /rootDesc.xml",                            "Generic",     "T1046"),
    19: AttackPattern(PatternID.MITRE_T1046_NETSCAN,     "MITRE_T1046_NETSCAN",     "B", ["tcp"],             "SYN across >5 ports, no ACK, <100ms between",                     "Generic",     "T1046"),
    20: AttackPattern(PatternID.SLOW_RECON,              "SLOW_RECON",              "B", ["tcp"],             "1 connection every 5–60 min over 24h",                            "APT",         "T1046"),
    # ── Group C — Exploitation Attempts ──────────────────────────────────────
    21: AttackPattern(PatternID.SHELLSHOCK,              "SHELLSHOCK",              "C", ["http"],            "() { :;}; in User-Agent or headers",                              "Generic",     "T1059"),
    22: AttackPattern(PatternID.DASAN_RCE,               "DASAN_RCE",               "C", ["http"],            "GET /GponForm/diag_Form?images/ with cmd injection",               "Generic",     "T1203"),
    23: AttackPattern(PatternID.HUAWEI_HG532_RCE,        "HUAWEI_HG532_RCE",        "C", ["http"],            "POST /ctrlt/DeviceUpgrade_1 with NewStatusURL injection",          "Generic",     "T1203"),
    24: AttackPattern(PatternID.REALTEK_SDK_RCE,         "REALTEK_SDK_RCE",         "C", ["http"],            "POST /soap.cgi UPnP SUBSCRIBE with shell commands",               "Generic",     "T1203"),
    25: AttackPattern(PatternID.BUFFER_OVERFLOW_TELNET,  "BUFFER_OVERFLOW_TELNET",  "C", ["telnet"],          ">256 bytes in single line, NOP sled pattern",                     "Generic",     "T1203"),
    26: AttackPattern(PatternID.DIR_TRAVERSAL_HTTP,      "DIR_TRAVERSAL_HTTP",      "C", ["http"],            "../ sequences in URL, attempts /etc/passwd or /proc/",            "Generic",     "T1083"),
    27: AttackPattern(PatternID.COMMAND_INJECTION_HTTP,  "COMMAND_INJECTION_HTTP",  "C", ["http"],            ";, |, && or backtick in form fields or GET params",               "Generic",     "T1059.004"),
    28: AttackPattern(PatternID.MQTT_MALICIOUS_PUBLISH,  "MQTT_MALICIOUS_PUBLISH",  "C", ["mqtt"],            "PUBLISH to cmnd/ or zigbee2mqtt/ with shell payload",             "Generic",     "T1499"),
    29: AttackPattern(PatternID.LOG4SHELL_PROBE,         "LOG4SHELL_PROBE",         "C", ["http"],            "${jndi:ldap:// in any header or body field",                      "Generic",     "T1203"),
    30: AttackPattern(PatternID.SPRING4SHELL_PROBE,      "SPRING4SHELL_PROBE",      "C", ["http"],            "POST with class.module.classLoader parameter",                    "Generic",     "T1203"),
    # ── Group D — Post-Exploitation ──────────────────────────────────────────
    31: AttackPattern(PatternID.WGET_DROPPER,            "WGET_DROPPER",            "D", ["telnet","ssh"],    "wget http:// or curl http:// post-auth",                          "Mirai",       "T1105"),
    32: AttackPattern(PatternID.BUSYBOX_WGET_CHAIN,      "BUSYBOX_WGET_CHAIN",      "D", ["telnet"],          "/bin/busybox wget + SATORI or ECCHI suffix",                      "Satori",      "T1105"),
    33: AttackPattern(PatternID.CHMOD_EXECUTE,           "CHMOD_EXECUTE",           "D", ["telnet","ssh"],    "chmod +x followed immediately by ./ execution",                  "Generic",     "T1059"),
    34: AttackPattern(PatternID.CRONTAB_PERSISTENCE,     "CRONTAB_PERSISTENCE",     "D", ["telnet","ssh"],    "crontab -e or echo >> /etc/cron",                                 "APT",         "T1053"),
    35: AttackPattern(PatternID.IPTABLES_MANIPULATION,   "IPTABLES_MANIPULATION",   "D", ["telnet","ssh"],    "iptables -F or iptables -A rule insertion",                       "Generic",     "T1562"),
    36: AttackPattern(PatternID.CRYPTO_MINER_INSTALL,    "CRYPTO_MINER_INSTALL",    "D", ["telnet","ssh"],    "xmrig, minerd, or mining pool URL reference",                     "Cryptojacker","T1496"),
    37: AttackPattern(PatternID.C2_CALLBACK_ATTEMPT,     "C2_CALLBACK_ATTEMPT",     "D", ["telnet","ssh"],    "nc, ncat, or bash -i >& /dev/tcp/ reverse shell",                 "APT",         "T1059"),
    38: AttackPattern(PatternID.SELF_PROPAGATION,        "SELF_PROPAGATION",        "D", ["telnet","ssh"],    "for i in loop scanning subnet and attempting login",              "Worm",        "T1210"),
    39: AttackPattern(PatternID.LOG_WIPE,                "LOG_WIPE",                "D", ["telnet","ssh"],    "rm /var/log/, echo > /var/log/messages, history -c",             "APT",         "T1070"),
    # ── Group E — Timing & Protocol ──────────────────────────────────────────
    40: AttackPattern(PatternID.HAWKES_BURST_A,          "HAWKES_BURST_A",          "E", ["any"],             ">20 events/min burst then silence >30 min",                       "Generic",     "T1498"),
    41: AttackPattern(PatternID.HAWKES_BURST_B,          "HAWKES_BURST_B",          "E", ["any"],             "5-15/min sustained over >2 hours",                                "Generic",     "T1498"),
    42: AttackPattern(PatternID.HAWKES_PERIODIC,         "HAWKES_PERIODIC",         "E", ["any"],             "regular inter-arrival time, CV < 0.3",                            "Generic",     "T1498"),
    43: AttackPattern(PatternID.DIURNAL_NIGHT,           "DIURNAL_NIGHT",           "E", ["any"],             "attacks concentrate 00:00-06:00 UTC",                             "Generic",     "T1498"),
    44: AttackPattern(PatternID.MULTI_PROTOCOL_CHAIN,    "MULTI_PROTOCOL_CHAIN",    "E", ["telnet","http","mqtt"], "same IP hits Telnet+HTTP+MQTT within 60s",                  "Generic",     "T1046"),
    45: AttackPattern(PatternID.TLS_DOWNGRADE,           "TLS_DOWNGRADE",           "E", ["ssh","https"],     "SSLv3/TLS1.0 attempt after TLS1.3 rejection",                    "Generic",     "T1562"),
    46: AttackPattern(PatternID.MQTT_QOS_ABUSE,          "MQTT_QOS_ABUSE",          "E", ["mqtt"],            "rapid QoS 2 publishes to exhaust broker state",                  "Generic",     "T1499"),
    47: AttackPattern(PatternID.ZERO_DAY_ANOMALY,        "ZERO_DAY_ANOMALY",        "E", ["any"],             "anomaly score > threshold; no pattern 1-46 matched",             "Unknown",     "T1203"),
}

# Convenience lookup by name
PATTERN_BY_NAME: dict[str, AttackPattern] = {p.name: p for p in PATTERNS.values()}
