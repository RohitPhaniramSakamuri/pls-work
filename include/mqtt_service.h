#ifndef MQTT_SERVICE_H
#define MQTT_SERVICE_H

#include <PubSubClient.h>
#include <WiFiClient.h>
#include <WiFiServer.h>

// Shared MQTT client — declared here, defined in mqtt_service.cpp, used by EventLogger
extern PubSubClient mqttClient;

class MQTTService {
public:
    // Connect to the backend MQTT broker (for event publishing)
    static void begin(const char* brokerIp, uint16_t brokerPort, const char* nodeId);
    // Start honeypot listener on port 1883
    static void beginHoneypot(uint16_t port);
    // Call from loop() — maintains broker connection and processes incoming honeypot connections
    static void loop();

    // Exposed so PubSubClient can be constructed against it in .cpp
    static WiFiClient _wifiClient;

private:
    static WiFiServer* _honeypotServer;
    static char _nodeId[16];
    static unsigned long _lastReconnect;
    static void _reconnect();
    static void _handleHoneypotClient(WiFiClient client);
    static uint16_t _parseConnectPacket(const uint8_t* buf, size_t len,
                                         char* clientId, char* username, char* password);
};

#endif // MQTT_SERVICE_H
