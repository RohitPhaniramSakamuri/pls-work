#ifndef TELNET_HONEYPOT_H
#define TELNET_HONEYPOT_H

#include <WiFiServer.h>
#include "attack_patterns.h"

enum TelnetState {
    STATE_BANNER,
    STATE_LOGIN,
    STATE_PASSWORD,
    STATE_SHELL
};

struct TelnetClient {
    WiFiClient    client;
    TelnetState   state;
    String        buffer;
    bool          authenticated;
    SessionContext ctx;   // tracks per-session state for classifier
};

class TelnetHoneypot {
public:
    static void begin(int port);
    static void loop();
private:
    static WiFiServer* _server;
    static TelnetClient _clients[5];
    static uint8_t _clientCount;
    static void _handleClient(TelnetClient& tc);
    static void _handleCommand(TelnetClient& tc, const String& cmd);
    static void _removeClient(uint8_t idx);
};

#endif // TELNET_HONEYPOT_H
