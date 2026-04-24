#include "tls_honeypot.h"
#include "event_logger.h"
#include "attack_patterns.h"
#include <Arduino.h>

AsyncServer* TLSHoneypot::_server = nullptr;

// ── Per-session scratch buffer (shared across connections) ────────────────────
// Max 3 concurrent TLS probes; state held inside AsyncClient user context.
struct TLSSession {
    char     src_ip[16];
    uint8_t  buf[512];
    uint16_t buf_len;
    bool     responded;
    SessionContext ctx;
};

static TLSSession _sessions[3];
static uint8_t    _sessionCount = 0;

static TLSSession* _alloc(const char* ip) {
    for (int i = 0; i < 3; i++) {
        if (_sessions[i].src_ip[0] == '\0') {
            memset(&_sessions[i], 0, sizeof(TLSSession));
            strncpy(_sessions[i].src_ip, ip, 15);
            return &_sessions[i];
        }
    }
    // Evict oldest (slot 0)
    memset(&_sessions[0], 0, sizeof(TLSSession));
    strncpy(_sessions[0].src_ip, ip, 15);
    return &_sessions[0];
}

static void _free(TLSSession* s) {
    if (s) s->src_ip[0] = '\0';
}

// ── Cipher suite helpers ──────────────────────────────────────────────────────

bool TLSHoneypot::_isWeakCipher(uint16_t cipher) {
    switch (cipher) {
        case CIPHER_RC4_SHA:
        case CIPHER_RC4_MD5:
        case CIPHER_3DES_SHA:
        case CIPHER_NULL_MD5:
        case CIPHER_EXPORT_RC4_40:
        case 0x0002:  // TLS_RSA_WITH_NULL_SHA
        case 0x0000:  // TLS_NULL_WITH_NULL_NULL
            return true;
        default:
            return false;
    }
}

// Parse cipher suite list from a ClientHello starting at the ciphers length field.
// Returns the first weak cipher found (or CIPHER_RC4_SHA as default).
// Writes a comma-separated hex list to out[].
uint16_t TLSHoneypot::_parseCiphers(const uint8_t* buf, size_t len,
                                     char* out, size_t out_len) {
    uint16_t chosen = CIPHER_RC4_SHA;
    out[0] = '\0';
    if (len < 2) return chosen;

    uint16_t cipher_len = ((uint16_t)buf[0] << 8) | buf[1];
    size_t   offset     = 2;
    size_t   written    = 0;
    bool     found_weak = false;

    for (size_t i = 0; i + 1 < cipher_len && offset + i + 1 < len; i += 2) {
        uint16_t c = ((uint16_t)buf[offset + i] << 8) | buf[offset + i + 1];
        if (written + 7 < out_len) {
            written += snprintf(out + written, out_len - written, "%04X,", c);
        }
        if (!found_weak && _isWeakCipher(c)) {
            chosen     = c;
            found_weak = true;
        }
    }
    // Trim trailing comma
    if (written > 0 && out[written - 1] == ',') out[written - 1] = '\0';
    return chosen;
}

// ── TLS 1.0 ServerHello with weak cipher ─────────────────────────────────────
/*
 * Structure (RFC 5246):
 *   TLS Record:    [content_type=22][version=0x03,0x01][length 2B]
 *   Handshake:     [type=2][length 3B]
 *   ServerHello:   [version=0x03,0x01][random 32B][session_id_len=0]
 *                  [cipher_suite 2B][compression=0]
 */
void TLSHoneypot::_sendWeakServerHello(AsyncClient* client, uint16_t chosen_cipher) {
    // Deterministic "random" bytes — intentionally weak for honeypot purposes
    static const uint8_t FAKE_RANDOM[32] = {
        0xDE,0xAD,0xBE,0xEF, 0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F, 0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17, 0x18,0x19,0x1A,0x1B
    };

    // ServerHello body: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) = 38
    uint8_t pkt[5 + 4 + 38] = {0};
    uint8_t* p = pkt;

    // TLS Record header
    *p++ = TLS_CONTENT_HANDSHAKE;  // content_type
    *p++ = 0x03; *p++ = 0x01;      // TLS 1.0 version (deliberate downgrade)
    *p++ = 0x00; *p++ = 4 + 38;    // length = handshake header(4) + body(38)

    // Handshake header
    *p++ = TLS_HANDSHAKE_SERVERHELLO;
    *p++ = 0x00; *p++ = 0x00; *p++ = 38;  // length = 38

    // ServerHello body
    *p++ = 0x03; *p++ = 0x01;   // server version: TLS 1.0 (SSLv3.1) — intentionally old
    memcpy(p, FAKE_RANDOM, 32); p += 32;
    *p++ = 0x00;                // session_id length = 0
    *p++ = (uint8_t)(chosen_cipher >> 8);
    *p++ = (uint8_t)(chosen_cipher & 0xFF);
    *p++ = 0x00;                // compression: null

    client->add((const char*)pkt, sizeof(pkt));
    client->send();
}

// ── AsyncServer callbacks ─────────────────────────────────────────────────────

void TLSHoneypot::_onDisconnect(void* arg, AsyncClient* client) {
    TLSSession* s = (TLSSession*)arg;
    _free(s);
    delete client;
}

void TLSHoneypot::_onData(void* arg, AsyncClient* client, void* data, size_t len) {
    TLSSession* s = (TLSSession*)arg;
    if (!s || s->responded) return;

    // Buffer incoming bytes (up to 512)
    size_t copy = min(len, (size_t)(512 - s->buf_len));
    memcpy(s->buf + s->buf_len, data, copy);
    s->buf_len += copy;

    // Need at least a TLS record header (5 bytes) + handshake header (4) + ClientHello min
    if (s->buf_len < 9) return;

    bool is_tls    = (s->buf[0] == TLS_CONTENT_HANDSHAKE && s->buf[5] == TLS_HANDSHAKE_CLIENTHELLO);
    bool is_ssl2   = (s->buf[0] == 0x80 && s->buf[2] == 0x01);  // SSLv2 ClientHello
    bool is_plain  = (!is_tls && !is_ssl2);

    char cipher_str[128] = "raw-tcp";
    uint16_t chosen = CIPHER_RC4_SHA;

    if (is_tls) {
        // Skip record header(5) + handshake header(4) + HelloVersion(2) + Random(32) + SessionIDLen(1)
        size_t skip = 5 + 4 + 2 + 32 + 1;
        if (s->buf[skip - 1] > 0) skip += s->buf[skip - 1]; // skip session ID
        if (skip + 2 < s->buf_len) {
            chosen = _parseCiphers(s->buf + skip, s->buf_len - skip, cipher_str, sizeof(cipher_str));
        }
        _sendWeakServerHello(client, chosen);
    } else if (is_ssl2) {
        // SSLv2 — log and close (no response for safety)
        snprintf(cipher_str, sizeof(cipher_str), "SSLv2-hello");
    }

    // Build command field: tls_ver:cipher_list for event log
    char cmd_field[160];
    snprintf(cmd_field, sizeof(cmd_field), "tls_probe ciphers=[%s] chosen=%04X ssl2=%d raw=%d",
             cipher_str, chosen, is_ssl2 ? 1 : 0, is_plain ? 1 : 0);

    // Update session context for on-device classification
    s->ctx.input_max_len = (uint16_t)s->buf_len;
    strncpy(s->ctx.src_ip, s->src_ip, sizeof(s->ctx.src_ip) - 1);
    strncpy(s->ctx.proto,  "tls",    sizeof(s->ctx.proto)   - 1);
    strncpy(s->ctx.last_cmd, cmd_field, sizeof(s->ctx.last_cmd) - 1);
    s->ctx.banner_only = !is_tls && !is_ssl2;

    EventLogger::logEvent("tls", s->src_ip, "", "", cmd_field, "connect", &s->ctx);

    s->responded = true;
    // Close after a short delay to let ServerHello drain
    client->close(false);
}

void TLSHoneypot::_onClient(void* arg, AsyncClient* client) {
    if (!client) return;
    IPAddress ip = client->remoteIP();
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             ip[0], ip[1], ip[2], ip[3]);

    Serial.printf("[TLS] connection from %s\n", ip_str);

    TLSSession* s = _alloc(ip_str);
    // Pass session pointer as `arg` to each callback (AsyncClient API pattern)
    client->onData(_onData, s);
    client->onDisconnect(_onDisconnect, s);

    // Log raw connect event immediately
    EventLogger::logEvent("tls", ip_str, "", "", "", "connect", nullptr);
}

// ── Public API ─────────────────────────────────────────────────────────────────

void TLSHoneypot::begin(uint16_t port) {
    _server = new AsyncServer(port);
    _server->onClient(_onClient, nullptr);
    _server->begin();
    Serial.printf("[TLS] honeypot listening on port %u (weak cipher injection: RC4-SHA, 3DES, NULL)\n", port);
}

void TLSHoneypot::loop() {
    // AsyncServer is interrupt-driven; nothing to poll
}
