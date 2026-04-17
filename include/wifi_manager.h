#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <WiFi.h>

class WiFiManager {
public:
    static void begin(const char* ssid, const char* password);
    static bool isConnected();
    static void reconnectLoop(); // call from loop() for watchdog reconnect
private:
    static const char* _ssid;
    static const char* _password;
};

#endif // WIFI_MANAGER_H
