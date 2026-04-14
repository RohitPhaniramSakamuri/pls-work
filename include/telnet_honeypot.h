#ifndef TELNET_HONEYPOT_H
#define TELNET_HONEYPOT_H

#include <WiFiServer.h>
#include <vector>

enum TelnetState {
    STATE_LOGIN,
    STATE_PASSWORD,
    STATE_SHELL
};

struct TelnetClient {
    WiFiClient client;
    TelnetState state;
    String buffer;
};

class TelnetHoneypot {
public:
    static void setup(int port);
    static void loop();
private:
    static WiFiServer* server;
    static std::vector<TelnetClient> clients;
    static void handleClient(TelnetClient& tc);
};

#endif
