#include "logger.h"

std::vector<LogEntry> Logger::logs;
const size_t Logger::MAX_LOGS;

void Logger::log(String ip, String proto, String event, String data) {
    LogEntry entry;
    entry.timestamp = millis();
    entry.source_ip = ip;
    entry.protocol = proto;
    entry.event_type = event;
    entry.payload = data;

    if (logs.size() >= 50) {
        logs.erase(logs.begin());
    }
    logs.push_back(entry);

    // Serial output for debugging
    Serial.printf("[%lu] [%s] %s from %s: %s\n", 
        entry.timestamp, entry.protocol.c_str(), entry.event_type.c_str(), 
        entry.source_ip.c_str(), entry.payload.c_str());
}

std::vector<LogEntry>& Logger::getLogs() {
    return logs;
}

void Logger::clearLogs() {
    logs.clear();
}

String Logger::toJson(const LogEntry& entry) {
    StaticJsonDocument<512> doc;
    doc["timestamp"] = entry.timestamp;
    doc["source_ip"] = entry.source_ip;
    doc["protocol"] = entry.protocol;
    doc["event_type"] = entry.event_type;
    doc["payload"] = entry.payload;
    String out;
    serializeJson(doc, out);
    return out;
}
