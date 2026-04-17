#include "event_logger.h"
#include <PubSubClient.h>
#include <WiFi.h>
#include "secrets.h"

extern PubSubClient mqttClient;

HoneypotEvent EventLogger::_queue[50];
uint8_t EventLogger::_head = 0;
uint8_t EventLogger::_tail = 0;
uint8_t EventLogger::_count = 0;
char EventLogger::_nodeId[16] = "esp32-01";
unsigned long EventLogger::_lastFlush = 0;
unsigned long EventLogger::_mqttBackoff = 1000;
unsigned long EventLogger::_lastMqttAttempt = 0;

void EventLogger::_makeSessionId(char* out) {
    uint32_t rnd = esp_random();
    snprintf(out, 8, "%06x", rnd & 0xFFFFFF);
}

void EventLogger::begin(const char* nodeId) {
    strncpy(_nodeId, nodeId, sizeof(_nodeId) - 1);
    _nodeId[sizeof(_nodeId) - 1] = '\0';
    _head = 0; _tail = 0; _count = 0;
    _lastFlush = millis();
    _mqttBackoff = 1000;
    Serial.printf("[EventLogger] Initialized node=%s\n", _nodeId);
}

void EventLogger::logEvent(const char* proto,
                            const char* src_ip,
                            const char* username,
                            const char* password,
                            const char* command,
                            const char* event_type,
                            const SessionContext* ctx) {
    HoneypotEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.timestamp = (uint32_t)(millis() / 1000);
    strncpy(ev.proto,      proto,      sizeof(ev.proto)      - 1);
    strncpy(ev.src_ip,     src_ip,     sizeof(ev.src_ip)     - 1);
    strncpy(ev.username,   username,   sizeof(ev.username)   - 1);
    strncpy(ev.password,   password,   sizeof(ev.password)   - 1);
    strncpy(ev.command,    command,    sizeof(ev.command)    - 1);
    strncpy(ev.event_type, event_type, sizeof(ev.event_type) - 1);
    strncpy(ev.node,       _nodeId,    sizeof(ev.node)       - 1);

    // ── On-device classification ──────────────────────────────────────────
    if (ctx != nullptr) {
        ClassifyResult cr = classify_session(*ctx);
        ev.pattern_id  = (uint8_t)cr.pattern;
        ev.confidence  = cr.confidence;
        ev.attempt_num = ctx->attempt_num;
        ev.session_duration_ms = ctx->last_seen_ms - ctx->first_seen_ms;
        strncpy(ev.pattern_name,   patternName(cr.pattern),               sizeof(ev.pattern_name)   - 1);
        strncpy(ev.pattern_group,  patternGroup(cr.pattern),              sizeof(ev.pattern_group)  - 1);
        strncpy(ev.botnet_family,  BOTNET_FAMILIES[(uint8_t)cr.pattern],  sizeof(ev.botnet_family)  - 1);
        strncpy(ev.mitre_technique,MITRE_TECHNIQUES[(uint8_t)cr.pattern], sizeof(ev.mitre_technique)- 1);
        if (ctx->session_id[0] != '\0') {
            strncpy(ev.session_id, ctx->session_id, sizeof(ev.session_id) - 1);
        } else {
            _makeSessionId(ev.session_id);
        }
    } else {
        _makeSessionId(ev.session_id);
        ev.pattern_id = 0;
        ev.confidence = 0;
        strncpy(ev.pattern_name, "UNKNOWN", sizeof(ev.pattern_name) - 1);
        strncpy(ev.pattern_group, "?", sizeof(ev.pattern_group) - 1);
        strncpy(ev.botnet_family, "Unknown", sizeof(ev.botnet_family) - 1);
        strncpy(ev.mitre_technique, "T0000", sizeof(ev.mitre_technique) - 1);
    }

    Serial.printf("[EVENT] proto=%s src=%s user=%s evt=%s pattern=%s conf=%u\n",
                  proto, src_ip, username, event_type, ev.pattern_name, ev.confidence);

    if (_count == 50) { _head = (_head + 1) % 50; } else { _count++; }
    _queue[_tail] = ev;
    _tail = (_tail + 1) % 50;

    if (_isImmediate(event_type)) { _publishEvent(ev); }
}

bool EventLogger::_isImmediate(const char* event_type) {
    return (strcmp(event_type, "auth_success") == 0 ||
            strcmp(event_type, "command")      == 0 ||
            strcmp(event_type, "exploit")      == 0);
}

void EventLogger::_mqttTopic(const char* event_type, char* buf, size_t len) {
    if      (strcmp(event_type, "auth_attempt") == 0 || strcmp(event_type, "auth_success") == 0)
        snprintf(buf, len, "honeypot/events/auth");
    else if (strcmp(event_type, "connect")  == 0) snprintf(buf, len, "honeypot/events/connect");
    else if (strcmp(event_type, "command")  == 0) snprintf(buf, len, "honeypot/events/command");
    else if (strcmp(event_type, "exploit")  == 0) snprintf(buf, len, "honeypot/events/exploit");
    else snprintf(buf, len, "honeypot/events/heartbeat");
}

bool EventLogger::_publishEvent(const HoneypotEvent& ev) {
    if (!mqttClient.connected()) return false;
    unsigned long now = millis();
    if (now - _lastMqttAttempt < _mqttBackoff) return false;
    _lastMqttAttempt = now;

    char topic[48];
    _mqttTopic(ev.event_type, topic, sizeof(topic));

    StaticJsonDocument<512> doc;
    doc["ts"]               = ev.timestamp;
    doc["proto"]            = ev.proto;
    doc["src_ip"]           = ev.src_ip;
    doc["user"]             = ev.username;
    doc["pass"]             = ev.password;
    doc["cmd"]              = ev.command;
    doc["evt"]              = ev.event_type;
    doc["node"]             = ev.node;
    doc["pattern_id"]       = ev.pattern_id;
    doc["pattern_name"]     = ev.pattern_name;
    doc["pattern_group"]    = ev.pattern_group;
    doc["confidence"]       = ev.confidence;
    doc["session_id"]       = ev.session_id;
    doc["attempt_num"]      = ev.attempt_num;
    doc["session_dur_ms"]   = ev.session_duration_ms;
    doc["botnet_family"]    = ev.botnet_family;
    doc["mitre"]            = ev.mitre_technique;

    char payload[512];
    size_t n = serializeJson(doc, payload, sizeof(payload));
    bool ok = mqttClient.publish(topic, payload, n);
    if (ok) { _mqttBackoff = 1000; }
    else    { _mqttBackoff = min(_mqttBackoff * 2, (unsigned long)30000); }
    return ok;
}

void EventLogger::flushQueue() {
    if (_count == 0) return;
    uint8_t idx = _head;
    for (uint8_t i = 0; i < _count; i++) {
        _publishEvent(_queue[idx]);
        idx = (idx + 1) % 50;
    }
    _head = 0; _tail = 0; _count = 0;
    _mqttBackoff = 1000;
}

void EventLogger::loop() {
    unsigned long now = millis();
    if (now - _lastFlush >= 30000) {
        _lastFlush = now;
        flushQueue();
        if (mqttClient.connected()) {
            StaticJsonDocument<256> hb;
            hb["ts"]        = (uint32_t)(now / 1000);
            hb["evt"]       = "heartbeat";
            hb["node"]      = _nodeId;
            hb["free_heap"] = ESP.getFreeHeap();
            hb["uptime_s"]  = (uint32_t)(now / 1000);
            hb["pattern_id"]= 0;
            char buf[256];
            size_t n = serializeJson(hb, buf, sizeof(buf));
            mqttClient.publish("honeypot/events/heartbeat", buf, n);
        }
    }
}
