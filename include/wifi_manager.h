#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <WiFi.h>

class WiFiManager {
public:
    static void setup(const char* ssid, const char* password);
    static bool isConnected();
};

#endif
