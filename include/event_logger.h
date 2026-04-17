#ifndef EVENT_LOGGER_H
#define EVENT_LOGGER_H

#include <Arduino.h>
#include <ArduinoJson.h>
#include "attack_patterns.h"

struct HoneypotEvent {
    uint32_t timestamp;
    char proto[8];
    char src_ip[16];
    char username[32];
    char password[32];
    char command[128];
    char event_type[24];
    char node[16];
    // Phase 2 — pattern classification fields
    uint8_t  pattern_id;
    char     pattern_name[36];
    char     pattern_group[3];
    uint8_t  confidence;        // 0–100
    char     session_id[8];     // 6-char hex + null
    uint8_t  attempt_num;
    uint32_t session_duration_ms;
    char     botnet_family[20];
    char     mitre_technique[12];
};

class EventLogger {
public:
    static void begin(const char* nodeId);
    static void logEvent(const char* proto,
                         const char* src_ip,
                         const char* username,
                         const char* password,
                         const char* command,
                         const char* event_type,
                         const SessionContext* ctx = nullptr);
    static void flushQueue();
    static void loop();

private:
    static HoneypotEvent _queue[50];
    static uint8_t _head;
    static uint8_t _tail;
    static uint8_t _count;
    static char _nodeId[16];
    static unsigned long _lastFlush;
    static unsigned long _mqttBackoff;
    static unsigned long _lastMqttAttempt;
    static bool _isImmediate(const char* event_type);
    static bool _publishEvent(const HoneypotEvent& ev);
    static void _mqttTopic(const char* event_type, char* buf, size_t len);
    static void _makeSessionId(char* out);   // generate 6-char hex id
};

#endif // EVENT_LOGGER_H
