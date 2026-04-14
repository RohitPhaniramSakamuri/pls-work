#include "ssh_honeypot.h"
#include "logger.h"

WiFiServer* SSHHoneypot::server = nullptr;

void SSHHoneypot::setup(int port) {
    server = new WiFiServer(port);
    server->begin();
}

void SSHHoneypot::loop() {
    if (server->hasClient()) {
        WiFiClient client = server->available();
        String ip = client.remoteIP().toString();
        Logger::log(ip, "SSH", "connection", "Handshake attempt");
        client.println("SSH-2.0-OpenSSH_5.3");
        client.stop();
    }
}
