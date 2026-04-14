#include <Arduino.h>
#include "wifi_manager.h"
#include "http_honeypot.h"
#include "telnet_honeypot.h"
#include "ssh_honeypot.h"
#include "webhook.h"
#include "logger.h"

const char* SSID = "Honor10Lite";
const char* PASS = "AJBfifa2k20";
const char* WEBHOOK_URL = "http://your-backend.com/webhook";

AsyncWebServer server(80);
unsigned long last_ip_print = 0;

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("ESP32 IoT Honeypot Starting...");

    WiFiManager::setup(SSID, PASS);
    
    HTTPHoneypot::setup(server);
    server.begin();
    Serial.println("HTTP Honeypot started on port 80");

    TelnetHoneypot::setup(23);
    Serial.println("Telnet Honeypot started on port 23");

    SSHHoneypot::setup(22);
    Serial.println("SSH Honeypot started on port 22");

    Webhook::setup(WEBHOOK_URL);
    
    Logger::log("0.0.0.0", "SYSTEM", "boot", "Honeypot initialized");
}

void loop() {
    TelnetHoneypot::loop();
    SSHHoneypot::loop();
    Webhook::loop();
    
    if (millis() - last_ip_print > 5000) {
        Serial.print("Current IP: ");
        Serial.println(WiFi.localIP());
        last_ip_print = millis();
    }
    delay(10);
}
