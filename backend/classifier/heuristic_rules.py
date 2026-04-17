"""
heuristic_rules.py — deterministic rule matching for Groups A–D.
Each function takes a session dict (from InfluxDB pivot query) and returns
(PatternID, confidence 0.0–1.0) or None if no match.
"""
import re
from typing import Optional, Tuple
from patterns import PatternID

# ── Mirai / known cred lists ─────────────────────────────────────────────────
MIRAI_FIRST_3 = {("root","xc3511"),("root","vizxv"),("root","888888"),("root","default"),("root","")}
MIRAI_ADMIN   = {("admin","admin"),("admin","1234"),("admin","password"),("admin","")}
MOZI_CREDS    = {("root","root"),("Admin","Admin"),("admin",""),("root","admin")}
SATORI_CREDS  = {("root","Zte521"),("supervisor",""),("root","7ujMko0vizxv")}
FBOT_CREDS    = {("supervisor","zyad1234"),("telecomadmin","admintelecom"),("admin","1234")}
GAFGYT_CREDS  = {("root","888888"),("root","default"),("root","1234")}

# ── Helper ────────────────────────────────────────────────────────────────────
def _has(text: str, *substrings: str) -> bool:
    if not text: return False
    t = text.lower()
    return any(s.lower() in t for s in substrings)


# ── Group A ───────────────────────────────────────────────────────────────────

def match_credential_patterns(session: dict) -> Optional[Tuple[PatternID, float]]:
    user     = session.get("user", "") or ""
    pw       = session.get("pass", "") or ""
    attempts = int(session.get("attempt_count", 1))
    proto    = session.get("proto", "") or ""
    dur_ms   = float(session.get("session_dur_ms", 9999))

    if _has(pw, "t0talc0ntr0l4!"):
        return (PatternID.CONTROL4_TARGETED, 0.97)

    if (user, pw) in SATORI_CREDS or _has(pw, "Zte521"):
        return (PatternID.SATORI_HUAWEI, 0.90)

    if (user, pw) in FBOT_CREDS:
        return (PatternID.FBOT_FBXROUTER, 0.92)

    if (user, pw) in GAFGYT_CREDS and dur_ms < 500:
        return (PatternID.GAFGYT_DEFAULT, 0.85)

    if (user, pw) in MIRAI_FIRST_3 and attempts <= 3:
        return (PatternID.MIRAI_DEFAULT_CREDS, 0.88)

    if (user, pw) in MIRAI_ADMIN and attempts >= 2:
        return (PatternID.MIRAI_ADMIN_SWEEP, 0.82)

    if (user, pw) in MOZI_CREDS:
        return (PatternID.MOZI_ROUTER_CREDS, 0.80)

    if attempts == 1 and (user, pw) in {("admin","admin"),("root","root")}:
        return (PatternID.SINGLE_SHOT_DEFAULT, 0.75)

    if attempts > 10 and dur_ms < 60000:
        return (PatternID.GENERIC_DICT_FAST, 0.72)

    if proto == "http" and _has(session.get("cmd",""), "base64", "application/json"):
        return (PatternID.CREDENTIAL_STUFFING, 0.78)

    if dur_ms > 30000 and attempts >= 1:
        return (PatternID.HAJIME_SLOW_BRUTE, 0.65)

    return None


# ── Group B ───────────────────────────────────────────────────────────────────

def match_recon_patterns(session: dict) -> Optional[Tuple[PatternID, float]]:
    cmd    = session.get("cmd", "") or ""
    proto  = session.get("proto", "") or ""
    evt    = session.get("evt", "") or ""

    if evt == "connect" and not session.get("user") and not session.get("cmd"):
        return (PatternID.BANNER_GRAB_ONLY, 0.88)

    if _has(cmd, "/cgi-bin/", "/shell", "/command", "/cmd"):
        return (PatternID.CGI_PROBE, 0.82)

    if _has(cmd, "description.xml", "rootDesc.xml", "upnp"):
        return (PatternID.UPNP_PROBE, 0.87)

    if _has(cmd, "favicon.ico") or (proto == "http" and _has(cmd, "HEAD /")):
        return (PatternID.HTTP_FINGERPRINT, 0.75)

    if proto == "mqtt" and _has(cmd, "#", "$SYS"):
        return (PatternID.MQTT_TOPIC_ENUM, 0.85)

    return None


# ── Group C ───────────────────────────────────────────────────────────────────

_CVE_PATTERNS = [
    (re.compile(r"\(\) \{ :;\}"),                          PatternID.SHELLSHOCK,           0.97),
    (re.compile(r"GponForm|diag_Form"),                    PatternID.DASAN_RCE,            0.93),
    (re.compile(r"DeviceUpgrade|NewStatusURL"),             PatternID.HUAWEI_HG532_RCE,     0.93),
    (re.compile(r"soap\.cgi|SUBSCRIBE.*shell"),            PatternID.REALTEK_SDK_RCE,      0.90),
    (re.compile(r"\$\{jndi:", re.IGNORECASE),              PatternID.LOG4SHELL_PROBE,      0.97),
    (re.compile(r"class\.module\.classLoader"),            PatternID.SPRING4SHELL_PROBE,   0.95),
    (re.compile(r"cmnd/|zigbee2mqtt"),                     PatternID.MQTT_MALICIOUS_PUBLISH,0.88),
    (re.compile(r"\.\./|\.\.%2[Ff]|etc/passwd"),           PatternID.DIR_TRAVERSAL_HTTP,   0.85),
    (re.compile(r"[;&|`].*\b(sh|bash|cmd)\b|&&|`.*`"),    PatternID.COMMAND_INJECTION_HTTP,0.78),
]

def match_exploit_patterns(session: dict) -> Optional[Tuple[PatternID, float]]:
    payload = " ".join([
        session.get("cmd",  "") or "",
        session.get("user", "") or "",
        session.get("pass", "") or "",
    ])
    input_len = int(session.get("input_max_len", 0) or 0)

    if input_len > 256:
        return (PatternID.BUFFER_OVERFLOW_TELNET, 0.80)

    for pattern, pid, conf in _CVE_PATTERNS:
        if pattern.search(payload):
            return (pid, conf)

    return None


# ── Group D ───────────────────────────────────────────────────────────────────

_POST_EXPLOIT = [
    (re.compile(r"xmrig|minerd|pool\.(supportxmr|moneroocean|nanopool)"), PatternID.CRYPTO_MINER_INSTALL,  0.95),
    (re.compile(r"bash\s+-i|/dev/tcp|ncat\s|^\s*nc\s"),                   PatternID.C2_CALLBACK_ATTEMPT,   0.92),
    (re.compile(r"crontab\s+-e|>>\s*/etc/cron"),                          PatternID.CRONTAB_PERSISTENCE,   0.90),
    (re.compile(r"iptables\s+(-F|-A|-D)"),                                PatternID.IPTABLES_MANIPULATION,  0.90),
    (re.compile(r"history\s+-c|rm\s+/var/log|echo\s+>\s+/var/log"),       PatternID.LOG_WIPE,              0.88),
    (re.compile(r"for\s+i\s+in.*telnet|for\s+ip\s+in"),                   PatternID.SELF_PROPAGATION,      0.90),
    (re.compile(r"chmod\s+\+x.+&&.+\./|chmod.*\./"),                      PatternID.CHMOD_EXECUTE,         0.88),
    (re.compile(r"/bin/busybox\s+wget.+(SATORI|ECCHI)"),                   PatternID.BUSYBOX_WGET_CHAIN,    0.95),
    (re.compile(r"wget\s+http|curl\s+http"),                               PatternID.WGET_DROPPER,          0.85),
]

def match_postexploit_patterns(session: dict) -> Optional[Tuple[PatternID, float]]:
    cmd = session.get("cmd", "") or ""
    for pattern, pid, conf in _POST_EXPLOIT:
        if pattern.search(cmd):
            return (pid, conf)
    return None


# ── Master classifier ─────────────────────────────────────────────────────────

def classify(session: dict) -> Tuple[PatternID, float]:
    """Run all rule groups in priority order. Returns (PatternID, confidence)."""
    # On-device already tagged it — trust if confidence > 0.5
    dev_conf = int(session.get("confidence", 0) or 0) / 100.0
    dev_pid  = int(session.get("pattern_id", 0) or 0)
    if dev_conf >= 0.5 and dev_pid not in (0, 47):
        return (PatternID(dev_pid), min(dev_conf + 0.15, 1.0))  # backend bumps confidence

    for matcher in [match_postexploit_patterns, match_exploit_patterns,
                    match_recon_patterns, match_credential_patterns]:
        result = matcher(session)
        if result:
            return result

    return (PatternID.ZERO_DAY_ANOMALY, 0.30)
