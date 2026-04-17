#ifndef ATTACK_PATTERNS_H
#define ATTACK_PATTERNS_H

#include <Arduino.h>
#include <string.h>

// ─── 47-Pattern Taxonomy ─────────────────────────────────────────────────────

enum AttackPattern : uint8_t {
    PATTERN_UNKNOWN              = 0,
    // Group A — Credential Brute Force
    PATTERN_MIRAI_DEFAULT_CREDS  = 1,
    PATTERN_MIRAI_ADMIN_SWEEP    = 2,
    PATTERN_MOZI_ROUTER_CREDS    = 3,
    PATTERN_HAJIME_SLOW_BRUTE    = 4,
    PATTERN_CONTROL4_TARGETED    = 5,
    PATTERN_GAFGYT_DEFAULT       = 6,
    PATTERN_SATORI_HUAWEI        = 7,
    PATTERN_FBOT_FBXROUTER       = 8,
    PATTERN_GENERIC_DICT_FAST    = 9,
    PATTERN_CREDENTIAL_STUFFING  = 10,
    PATTERN_SINGLE_SHOT_DEFAULT  = 11,
    PATTERN_SUBNET_COORDINATED   = 12,
    // Group B — Reconnaissance & Scanning
    PATTERN_PORT_SCAN_SEQUENTIAL = 13,
    PATTERN_BANNER_GRAB_ONLY     = 14,
    PATTERN_HTTP_FINGERPRINT     = 15,
    PATTERN_CGI_PROBE            = 16,
    PATTERN_MQTT_TOPIC_ENUM      = 17,
    PATTERN_UPNP_PROBE           = 18,
    PATTERN_MITRE_T1046_NETSCAN  = 19,
    PATTERN_SLOW_RECON           = 20,
    // Group C — Exploitation Attempts
    PATTERN_SHELLSHOCK           = 21,
    PATTERN_DASAN_RCE            = 22,
    PATTERN_HUAWEI_HG532_RCE     = 23,
    PATTERN_REALTEK_SDK_RCE      = 24,
    PATTERN_BUFFER_OVERFLOW_TELNET = 25,
    PATTERN_DIR_TRAVERSAL_HTTP   = 26,
    PATTERN_COMMAND_INJECTION_HTTP = 27,
    PATTERN_MQTT_MALICIOUS_PUBLISH = 28,
    PATTERN_LOG4SHELL_PROBE      = 29,
    PATTERN_SPRING4SHELL_PROBE   = 30,
    // Group D — Post-Exploitation
    PATTERN_WGET_DROPPER         = 31,
    PATTERN_BUSYBOX_WGET_CHAIN   = 32,
    PATTERN_CHMOD_EXECUTE        = 33,
    PATTERN_CRONTAB_PERSISTENCE  = 34,
    PATTERN_IPTABLES_MANIPULATION = 35,
    PATTERN_CRYPTO_MINER_INSTALL = 36,
    PATTERN_C2_CALLBACK_ATTEMPT  = 37,
    PATTERN_SELF_PROPAGATION     = 38,
    PATTERN_LOG_WIPE             = 39,
    // Group E — Timing & Protocol
    PATTERN_HAWKES_BURST_A       = 40,
    PATTERN_HAWKES_BURST_B       = 41,
    PATTERN_HAWKES_PERIODIC      = 42,
    PATTERN_DIURNAL_NIGHT        = 43,
    PATTERN_MULTI_PROTOCOL_CHAIN = 44,
    PATTERN_TLS_DOWNGRADE        = 45,
    PATTERN_MQTT_QOS_ABUSE       = 46,
    PATTERN_ZERO_DAY_ANOMALY     = 47
};

// Human-readable names (indexed by AttackPattern value)
static const char* PATTERN_NAMES[] = {
    "UNKNOWN",
    "MIRAI_DEFAULT_CREDS", "MIRAI_ADMIN_SWEEP", "MOZI_ROUTER_CREDS",
    "HAJIME_SLOW_BRUTE", "CONTROL4_TARGETED", "GAFGYT_DEFAULT",
    "SATORI_HUAWEI", "FBOT_FBXROUTER", "GENERIC_DICT_FAST",
    "CREDENTIAL_STUFFING", "SINGLE_SHOT_DEFAULT", "SUBNET_COORDINATED",
    "PORT_SCAN_SEQUENTIAL", "BANNER_GRAB_ONLY", "HTTP_FINGERPRINT",
    "CGI_PROBE", "MQTT_TOPIC_ENUM", "UPNP_PROBE",
    "MITRE_T1046_NETSCAN", "SLOW_RECON",
    "SHELLSHOCK", "DASAN_RCE", "HUAWEI_HG532_RCE", "REALTEK_SDK_RCE",
    "BUFFER_OVERFLOW_TELNET", "DIR_TRAVERSAL_HTTP", "COMMAND_INJECTION_HTTP",
    "MQTT_MALICIOUS_PUBLISH", "LOG4SHELL_PROBE", "SPRING4SHELL_PROBE",
    "WGET_DROPPER", "BUSYBOX_WGET_CHAIN", "CHMOD_EXECUTE",
    "CRONTAB_PERSISTENCE", "IPTABLES_MANIPULATION", "CRYPTO_MINER_INSTALL",
    "C2_CALLBACK_ATTEMPT", "SELF_PROPAGATION", "LOG_WIPE",
    "HAWKES_BURST_A", "HAWKES_BURST_B", "HAWKES_PERIODIC",
    "DIURNAL_NIGHT", "MULTI_PROTOCOL_CHAIN", "TLS_DOWNGRADE",
    "MQTT_QOS_ABUSE", "ZERO_DAY_ANOMALY"
};

static const char* PATTERN_GROUPS[] = {
    "?",
    "A","A","A","A","A","A","A","A","A","A","A","A",
    "B","B","B","B","B","B","B","B",
    "C","C","C","C","C","C","C","C","C","C",
    "D","D","D","D","D","D","D","D","D",
    "E","E","E","E","E","E","E","E"
};

static const char* BOTNET_FAMILIES[] = {
    "Unknown",
    "Mirai","Mirai","Mozi","Hajime","Control4","Gafgyt","Satori","FBot",
    "Generic","Generic","Generic","Coordinated",
    "Masscan","Shodan","Generic","Generic","Generic","Generic","Generic","APT",
    "Generic","Generic","Generic","Generic","Generic","Generic","Generic",
    "Generic","Generic","Generic",
    "Mirai","Satori","Generic","APT","Generic","Cryptojacker","APT","Worm","APT",
    "Generic","Generic","Generic","Generic","Generic","Generic","Generic","Unknown"
};

static const char* MITRE_TECHNIQUES[] = {
    "T0000",
    "T1110.001","T1110.001","T1110.001","T1110.001","T1110.001","T1110.001",
    "T1110.001","T1110.001","T1110.001","T1110.001","T1110.001","T1110.001",
    "T1046","T1046","T1046","T1203","T1046","T1046","T1046","T1046",
    "T1059","T1203","T1203","T1203","T1203","T1083","T1059.004",
    "T1499","T1203","T1203",
    "T1105","T1105","T1059","T1053","T1562","T1496","T1059","T1210","T1070",
    "T1498","T1498","T1498","T1498","T1046","T1562","T1499","T1203"
};

// ─── Per-session state for on-device heuristic matching ──────────────────────

struct SessionContext {
    uint8_t  auth_attempt_count;
    uint8_t  attempt_num;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char     last_user[32];
    char     last_pass[32];
    char     last_cmd[128];
    char     proto[8];
    char     src_ip[16];
    char     session_id[8];
    bool     downloaded_file;
    bool     executed_file;
    bool     chmod_seen;
    bool     banner_only;    // connected + read banner, sent nothing
    bool     cgi_probed;
    uint16_t input_max_len;  // longest single line received
};

// ─── Heuristic Classifier ─────────────────────────────────────────────────────

// Returns confidence scaled 0–100 (on-device max = 70)
static uint8_t _conf(uint8_t base) { return base > 70 ? 70 : base; }

static bool _hasStr(const char* haystack, const char* needle) {
    return strstr(haystack, needle) != nullptr;
}

static bool _isMiraiFirst3(const SessionContext& ctx) {
    return (ctx.auth_attempt_count <= 3) &&
           (_hasStr(ctx.last_user, "root") &&
            (_hasStr(ctx.last_pass, "xc3511") || _hasStr(ctx.last_pass, "vizxv") ||
             _hasStr(ctx.last_pass, "888888") || _hasStr(ctx.last_pass, "default")));
}

struct ClassifyResult {
    AttackPattern pattern;
    uint8_t       confidence; // 0–100
};

inline ClassifyResult classify_session(const SessionContext& ctx) {
    const char* cmd  = ctx.last_cmd;
    const char* user = ctx.last_user;
    const char* pass = ctx.last_pass;
    uint32_t dur = ctx.last_seen_ms - ctx.first_seen_ms;

    // ── Group D (post-exploit) — highest specificity, check first ──────────
    if (_hasStr(cmd, "xmrig") || _hasStr(cmd, "minerd") || _hasStr(cmd, "pool.")) {
        return {PATTERN_CRYPTO_MINER_INSTALL, _conf(90)};
    }
    if (_hasStr(cmd, "bash -i") || _hasStr(cmd, "/dev/tcp") || _hasStr(cmd, "ncat") || _hasStr(cmd, " nc ")) {
        return {PATTERN_C2_CALLBACK_ATTEMPT, _conf(88)};
    }
    if (_hasStr(cmd, "crontab") || _hasStr(cmd, "/etc/cron")) {
        return {PATTERN_CRONTAB_PERSISTENCE, _conf(85)};
    }
    if (_hasStr(cmd, "iptables")) {
        return {PATTERN_IPTABLES_MANIPULATION, _conf(85)};
    }
    if (_hasStr(cmd, "history -c") || _hasStr(cmd, "rm /var/log") || _hasStr(cmd, "echo >")) {
        return {PATTERN_LOG_WIPE, _conf(85)};
    }
    if (_hasStr(cmd, "for i in") && _hasStr(cmd, "telnet")) {
        return {PATTERN_SELF_PROPAGATION, _conf(88)};
    }
    if (ctx.chmod_seen && ctx.executed_file) {
        return {PATTERN_CHMOD_EXECUTE, _conf(85)};
    }
    if (_hasStr(cmd, "/bin/busybox wget") &&
        (_hasStr(cmd, "SATORI") || _hasStr(cmd, "ECCHI"))) {
        return {PATTERN_BUSYBOX_WGET_CHAIN, _conf(90)};
    }
    if (ctx.downloaded_file || _hasStr(cmd, "wget http") || _hasStr(cmd, "curl http")) {
        return {PATTERN_WGET_DROPPER, _conf(80)};
    }

    // ── Group C (exploitation) ───────────────────────────────────────────────
    if (_hasStr(cmd, "${jndi:ldap") || _hasStr(cmd, "jndi:")) {
        return {PATTERN_LOG4SHELL_PROBE, _conf(95)};
    }
    if (_hasStr(cmd, "class.module.classLoader")) {
        return {PATTERN_SPRING4SHELL_PROBE, _conf(92)};
    }
    if (_hasStr(cmd, "() { :;}")) {
        return {PATTERN_SHELLSHOCK, _conf(95)};
    }
    if (_hasStr(cmd, "GponForm") || _hasStr(cmd, "diag_Form")) {
        return {PATTERN_DASAN_RCE, _conf(90)};
    }
    if (_hasStr(cmd, "DeviceUpgrade") || _hasStr(cmd, "NewStatusURL")) {
        return {PATTERN_HUAWEI_HG532_RCE, _conf(90)};
    }
    if (_hasStr(cmd, "soap.cgi") || _hasStr(cmd, "SUBSCRIBE")) {
        return {PATTERN_REALTEK_SDK_RCE, _conf(88)};
    }
    if (_hasStr(cmd, "cmnd/") || _hasStr(cmd, "zigbee2mqtt")) {
        return {PATTERN_MQTT_MALICIOUS_PUBLISH, _conf(85)};
    }
    if (ctx.input_max_len > 256) {
        return {PATTERN_BUFFER_OVERFLOW_TELNET, _conf(75)};
    }
    if (_hasStr(cmd, "../") || _hasStr(cmd, "..%2f") || _hasStr(cmd, "etc/passwd")) {
        return {PATTERN_DIR_TRAVERSAL_HTTP, _conf(80)};
    }
    if (_hasStr(cmd, ";") || _hasStr(cmd, "&&") || _hasStr(cmd, "| ")) {
        return {PATTERN_COMMAND_INJECTION_HTTP, _conf(70)};
    }

    // ── Group B (recon) ──────────────────────────────────────────────────────
    if (ctx.banner_only && ctx.auth_attempt_count == 0) {
        return {PATTERN_BANNER_GRAB_ONLY, _conf(85)};
    }
    if (ctx.cgi_probed) {
        return {PATTERN_CGI_PROBE, _conf(78)};
    }
    if (_hasStr(cmd, "/description.xml") || _hasStr(cmd, "rootDesc.xml")) {
        return {PATTERN_UPNP_PROBE, _conf(85)};
    }
    if (_hasStr(cmd, "favicon.ico") || (_hasStr(cmd, "HEAD /") && _hasStr(cmd, "GET /"))) {
        return {PATTERN_HTTP_FINGERPRINT, _conf(72)};
    }

    // ── Group A (credential) ─────────────────────────────────────────────────
    if (_hasStr(user, "root") && _hasStr(pass, "t0talc0ntr0l4!")) {
        return {PATTERN_CONTROL4_TARGETED, _conf(95)};
    }
    if ((_hasStr(user, "root") && _hasStr(pass, "Zte521")) ||
        _hasStr(user, "supervisor")) {
        return {PATTERN_SATORI_HUAWEI, _conf(88)};
    }
    if ((_hasStr(user, "supervisor") && _hasStr(pass, "zyad1234")) ||
        (_hasStr(user, "telecomadmin") && _hasStr(pass, "admintelecom"))) {
        return {PATTERN_FBOT_FBXROUTER, _conf(90)};
    }
    if (_hasStr(user, "root") &&
        (_hasStr(pass, "888888") || _hasStr(pass, "default")) &&
        dur < 500) {
        return {PATTERN_GAFGYT_DEFAULT, _conf(82)};
    }
    if (_isMiraiFirst3(ctx)) {
        return {PATTERN_MIRAI_DEFAULT_CREDS, _conf(70)};
    }
    if (_hasStr(user, "admin") &&
        (ctx.auth_attempt_count >= 2) &&
        (_hasStr(pass, "admin") || _hasStr(pass, "1234") || _hasStr(pass, "password"))) {
        return {PATTERN_MIRAI_ADMIN_SWEEP, _conf(68)};
    }
    if (_hasStr(user, "root") && _hasStr(pass, "root") &&
        (strncmp(ctx.proto, "http", 4) == 0 || strncmp(ctx.proto, "telnet", 6) == 0)) {
        return {PATTERN_MOZI_ROUTER_CREDS, _conf(70)};
    }
    if (dur > 30000 && ctx.auth_attempt_count >= 1) {
        return {PATTERN_HAJIME_SLOW_BRUTE, _conf(60)};
    }
    if (ctx.auth_attempt_count == 1 &&
        ((_hasStr(user, "admin") && _hasStr(pass, "admin")) ||
         (_hasStr(user, "root")  && _hasStr(pass, "root")))) {
        return {PATTERN_SINGLE_SHOT_DEFAULT, _conf(65)};
    }
    if (ctx.auth_attempt_count > 10 && dur < 60000) {
        return {PATTERN_GENERIC_DICT_FAST, _conf(62)};
    }

    // Default: unknown
    return {PATTERN_ZERO_DAY_ANOMALY, _conf(30)};
}

// Convenience: get pattern name string (safe, never out-of-bounds)
inline const char* patternName(AttackPattern p) {
    if (p > 47) return "UNKNOWN";
    return PATTERN_NAMES[(uint8_t)p];
}

inline const char* patternGroup(AttackPattern p) {
    if (p > 47) return "?";
    return PATTERN_GROUPS[(uint8_t)p];
}

#endif // ATTACK_PATTERNS_H
