#include <Arduino.h>
#include <ESPAsyncWebServer.h>
#include "secrets.h"
#include "wifi_manager.h"
#include "event_logger.h"
#include "mqtt_service.h"
#include "http_honeypot.h"
#include "telnet_honeypot.h"
#include "ssh_honeypot.h"

static AsyncWebServer httpServer(80);
static unsigned long lastIpPrint = 0;

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("=== ESP32 IoT Honeypot v2.0 ===");

    // 1. Wi-Fi
    WiFiManager::begin(WIFI_SSID, WIFI_PASSWORD);

    // 2. Event logger (must come before services that log)
    EventLogger::begin(NODE_ID);

    // 3. MQTT — connect to backend broker, start honeypot listener on 1883
    MQTTService::begin(MQTT_BROKER_IP, MQTT_BROKER_PORT, NODE_ID);
    MQTTService::beginHoneypot(1883);

    // 4. HTTP honeypot (port 80)
    HTTPHoneypot::begin(httpServer);

    // 5. Telnet honeypot (port 23)
    TelnetHoneypot::begin(23);

    // 6. SSH emulator (port 22)
    SSHHoneypot::begin(22);

    EventLogger::logEvent("system", "0.0.0.0", "", "", "boot", "connect");
    Serial.println("=== All services started ===");
}

void loop() {
    // Wi-Fi watchdog
    WiFiManager::reconnectLoop();

    // MQTT (broker connection + honeypot listener)
    MQTTService::loop();

    // Protocol honeypots
    TelnetHoneypot::loop();
    SSHHoneypot::loop();

    // Periodic event flush + heartbeat
    EventLogger::loop();

    // Periodic IP print for serial monitor
    if (millis() - lastIpPrint > 10000) {
        lastIpPrint = millis();
        Serial.printf("[Status] IP=%s FreeHeap=%u\n",
                      WiFi.localIP().toString().c_str(),
                      ESP.getFreeHeap());
    }
}
