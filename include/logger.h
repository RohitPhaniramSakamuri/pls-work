#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include <ArduinoJson.h>
#include <vector>

struct LogEntry {
    unsigned long timestamp;
    String source_ip;
    String protocol;
    String event_type;
    String payload; // JSON string
};

class Logger {
public:
    static void log(String ip, String proto, String event, String data);
    static std::vector<LogEntry>& getLogs();
    static void clearLogs();
    static String toJson(const LogEntry& entry);
private:
    static std::vector<LogEntry> logs;
    static const size_t MAX_LOGS = 50;
};

#endif
