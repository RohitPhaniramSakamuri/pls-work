#include "telnet_honeypot.h"
#include "logger.h"

WiFiServer* TelnetHoneypot::server = nullptr;
std::vector<TelnetClient> TelnetHoneypot::clients;

void TelnetHoneypot::setup(int port) {
    server = new WiFiServer(port);
    server->begin();
}

void TelnetHoneypot::loop() {
    if (server->hasClient()) {
        WiFiClient newClient = server->available();
        if (clients.size() < 5) {
            newClient.print("login: ");
            clients.push_back({newClient, STATE_LOGIN, ""});
        } else {
            newClient.stop();
        }
    }

    for (auto it = clients.begin(); it != clients.end(); ) {
        if (!it->client.connected()) {
            it = clients.erase(it);
        } else {
            handleClient(*it);
            it++;
        }
    }
}

void TelnetHoneypot::handleClient(TelnetClient& tc) {
    while (tc.client.available()) {
        char c = tc.client.read();
        if (c == '\r' || c == '\n') {
            String ip = tc.client.remoteIP().toString();
            if (tc.buffer.length() > 0) {
                if (tc.state == STATE_LOGIN) {
                    Logger::log(ip, "TELNET", "login", tc.buffer);
                    tc.client.print("password: ");
                    tc.state = STATE_PASSWORD;
                } else if (tc.state == STATE_PASSWORD) {
                    Logger::log(ip, "TELNET", "password", tc.buffer);
                    tc.client.println("\nWelcome to the IoT shell");
                    tc.client.print("root@iot-device:~# ");
                    tc.state = STATE_SHELL;
                } else if (tc.state == STATE_SHELL) {
                    Logger::log(ip, "TELNET", "command", tc.buffer);
                    if (tc.buffer == "ls") tc.client.println("bin  etc  home  lib  usr  var");
                    else if (tc.buffer == "cat /etc/passwd") tc.client.println("root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh");
                    else if (tc.buffer.startsWith("wget ") || tc.buffer.startsWith("curl ")) {
                        Logger::log(ip, "TELNET", "payload_url", tc.buffer);
                        tc.client.println("Connecting...");
                    } else tc.client.println("command not found: " + tc.buffer);
                    tc.client.print("root@iot-device:~# ");
                }
            } else if (tc.state == STATE_SHELL) tc.client.print("root@iot-device:~# ");
            tc.buffer = "";
        } else if (isprint(c)) tc.buffer += c;
    }
}
