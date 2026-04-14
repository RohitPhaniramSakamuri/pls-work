#include "webhook.h"
#include "logger.h"
#include <HTTPClient.h>

const char* Webhook::webhook_url = nullptr;
unsigned long Webhook::last_send = 0;

void Webhook::setup(const char* url) { webhook_url = url; }

void Webhook::loop() {
    if (webhook_url && (millis() - last_send > 30000)) {
        if (!Logger::getLogs().empty()) {
            HTTPClient http;
            http.begin(webhook_url);
            http.addHeader("Content-Type", "application/json");
            String payload = "[";
            auto& logs = Logger::getLogs();
            for (size_t i = 0; i < logs.size(); i++) {
                payload += Logger::toJson(logs[i]);
                if (i < logs.size() - 1) payload += ",";
            }
            payload += "]";
            int code = http.POST(payload);
            if (code > 0) Logger::clearLogs();
            http.end();
        }
        last_send = millis();
    }
}
