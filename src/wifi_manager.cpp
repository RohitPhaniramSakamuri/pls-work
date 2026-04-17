#include "wifi_manager.h"
#include <Arduino.h>

const char* WiFiManager::_ssid     = nullptr;
const char* WiFiManager::_password = nullptr;

void WiFiManager::begin(const char* ssid, const char* password) {
    _ssid     = ssid;
    _password = password;
    Serial.printf("[WiFi] Connecting to SSID: %s\n", ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
        if (millis() - start > 30000) {
            Serial.println("\n[WiFi] Timeout — retrying in 5s");
            delay(5000);
            WiFi.begin(ssid, password);
            start = millis();
        }
    }

    Serial.println();
    Serial.printf("[WiFi] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
}

bool WiFiManager::isConnected() {
    return WiFi.status() == WL_CONNECTED;
}

void WiFiManager::reconnectLoop() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] Lost connection — reconnecting...");
        WiFi.disconnect();
        WiFi.begin(_ssid, _password);
        unsigned long start = millis();
        while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
            delay(500);
            Serial.print(".");
        }
        if (WiFi.status() == WL_CONNECTED) {
            Serial.printf("\n[WiFi] Reconnected! IP: %s\n", WiFi.localIP().toString().c_str());
        } else {
            Serial.println("\n[WiFi] Reconnect failed — will retry next loop");
        }
    }
}
