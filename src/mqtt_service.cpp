#include "mqtt_service.h"
#include "event_logger.h"
#include <Arduino.h>

// Shared MQTT client (used by EventLogger)
WiFiClient MQTTService::_wifiClient;
PubSubClient mqttClient(MQTTService::_wifiClient);

WiFiServer* MQTTService::_honeypotServer = nullptr;
char MQTTService::_nodeId[16] = "esp32-01";
unsigned long MQTTService::_lastReconnect = 0;

void MQTTService::begin(const char* brokerIp, uint16_t brokerPort, const char* nodeId) {
    strncpy(_nodeId, nodeId, sizeof(_nodeId) - 1);
    mqttClient.setServer(brokerIp, brokerPort);
    mqttClient.setBufferSize(1024);
    Serial.printf("[MQTT] Broker: %s:%u  Node: %s\n", brokerIp, brokerPort, nodeId);
    _reconnect();
}

void MQTTService::beginHoneypot(uint16_t port) {
    _honeypotServer = new WiFiServer(port);
    _honeypotServer->begin();
    Serial.printf("[MQTT-Honeypot] Listening on port %u\n", port);
}

void MQTTService::_reconnect() {
    if (mqttClient.connected()) return;
    char clientId[32];
    snprintf(clientId, sizeof(clientId), "honeypot-%s", _nodeId);
    if (mqttClient.connect(clientId)) {
        Serial.println("[MQTT] Connected to broker");
    } else {
        Serial.printf("[MQTT] Connect failed, rc=%d\n", mqttClient.state());
    }
}

void MQTTService::loop() {
    // Maintain backend broker connection
    if (!mqttClient.connected()) {
        unsigned long now = millis();
        if (now - _lastReconnect >= 5000) {
            _lastReconnect = now;
            _reconnect();
        }
    }
    mqttClient.loop();

    // Handle honeypot connections
    if (_honeypotServer && _honeypotServer->hasClient()) {
        WiFiClient client = _honeypotServer->available();
        if (client) {
            _handleHoneypotClient(client);
        }
    }
}

void MQTTService::_handleHoneypotClient(WiFiClient client) {
    String ip = client.remoteIP().toString();
    EventLogger::logEvent("mqtt", ip.c_str(), "", "", "", "connect");

    // Read up to 256 bytes (enough for CONNECT + PUBLISH)
    uint8_t buf[256] = {0};
    size_t pos = 0;
    unsigned long deadline = millis() + 2000;
    while (client.connected() && pos < sizeof(buf) && millis() < deadline) {
        if (client.available()) {
            buf[pos++] = client.read();
        }
    }

    if (pos < 2) { client.stop(); return; }

    uint8_t msgType = (buf[0] >> 4) & 0x0F;

    if (msgType == 1) { // CONNECT (0x10)
        char clientId[64] = "";
        char username[64] = "";
        char password[64] = "";
        _parseConnectPacket(buf, pos, clientId, username, password);

        EventLogger::logEvent("mqtt", ip.c_str(), username, password, clientId, "auth_attempt");

        // Send CONNACK with return code 0x00 (accepted)
        uint8_t connack[] = {0x20, 0x02, 0x00, 0x00};
        client.write(connack, sizeof(connack));

        // Keep reading for PUBLISH packets
        deadline = millis() + 5000;
        pos = 0;
        while (client.connected() && pos < sizeof(buf) && millis() < deadline) {
            if (client.available()) {
                buf[pos++] = client.read();
            }
        }
        if (pos > 0 && ((buf[0] >> 4) & 0x0F) == 3) { // PUBLISH (0x30)
            // Extract topic from PUBLISH (bytes 2..3 = topic length, followed by topic)
            if (pos > 4) {
                uint16_t topicLen = ((uint16_t)buf[2] << 8) | buf[3];
                char topic[128] = "";
                if (topicLen < sizeof(topic) && (size_t)(4 + topicLen) <= pos) {
                    memcpy(topic, &buf[4], topicLen);
                    topic[topicLen] = '\0';
                }
                EventLogger::logEvent("mqtt", ip.c_str(), username, "", topic, "command");
            }
        }
    }

    client.stop();
}

uint16_t MQTTService::_parseConnectPacket(const uint8_t* buf, size_t len,
                                            char* clientId, char* username, char* password) {
    // Fixed header: buf[0]=0x10, buf[1]=remaining length
    // Variable header starts at buf[2]: protocol name length (2 bytes) + name + level + flags + keepalive
    if (len < 10) return 0;

    size_t idx = 2; // skip fixed header
    uint16_t protoNameLen = ((uint16_t)buf[idx] << 8) | buf[idx + 1];
    idx += 2 + protoNameLen; // skip protocol name
    if (idx + 4 > len) return 0;
    uint8_t connectFlags = buf[idx + 1];
    idx += 4; // protocol level (1) + connect flags (1) + keepalive (2)

    // Client ID
    if (idx + 2 > len) return 0;
    uint16_t cidLen = ((uint16_t)buf[idx] << 8) | buf[idx + 1];
    idx += 2;
    if (cidLen > 0 && idx + cidLen <= len) {
        size_t cpLen = cidLen < 63 ? cidLen : 63;
        memcpy(clientId, &buf[idx], cpLen);
        clientId[cpLen] = '\0';
    }
    idx += cidLen;

    // Username (flag bit 7)
    if (connectFlags & 0x80) {
        if (idx + 2 > len) return 0;
        uint16_t uLen = ((uint16_t)buf[idx] << 8) | buf[idx + 1];
        idx += 2;
        if (uLen > 0 && idx + uLen <= len) {
            size_t cpLen = uLen < 63 ? uLen : 63;
            memcpy(username, &buf[idx], cpLen);
            username[cpLen] = '\0';
        }
        idx += uLen;
    }

    // Password (flag bit 6)
    if (connectFlags & 0x40) {
        if (idx + 2 > len) return 0;
        uint16_t pLen = ((uint16_t)buf[idx] << 8) | buf[idx + 1];
        idx += 2;
        if (pLen > 0 && idx + pLen <= len) {
            size_t cpLen = pLen < 63 ? pLen : 63;
            memcpy(password, &buf[idx], cpLen);
            password[cpLen] = '\0';
        }
    }

    return (uint16_t)idx;
}
