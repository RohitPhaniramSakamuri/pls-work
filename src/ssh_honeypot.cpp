#include "ssh_honeypot.h"
#include "event_logger.h"

WiFiServer* SSHHoneypot::_server = nullptr;

// SSH-2.0 identification banner (deliberately old version to attract scanners)
static const char SSH_BANNER[] = "SSH-2.0-OpenSSH_7.4\r\n";

void SSHHoneypot::begin(int port) {
    _server = new WiFiServer(port);
    _server->begin();
    Serial.printf("[SSH] Listening on port %d\n", port);
}

void SSHHoneypot::loop() {
    if (!_server || !_server->hasClient()) return;

    WiFiClient client = _server->available();
    if (!client) return;

    String ip = client.remoteIP().toString();
    EventLogger::logEvent("ssh", ip.c_str(), "", "", "", "connect");

    // Send SSH identification string
    client.write((const uint8_t*)SSH_BANNER, sizeof(SSH_BANNER) - 1);

    // Read client banner + up to 512 bytes of key-exchange init
    char buf[512] = {0};
    size_t pos = 0;
    unsigned long deadline = millis() + 3000;

    while (client.connected() && pos < sizeof(buf) - 1 && millis() < deadline) {
        if (client.available()) {
            buf[pos++] = (char)client.read();
        }
    }
    buf[pos] = '\0';

    // Extract client banner (first line)
    char clientBanner[128] = "<no banner>";
    if (pos > 0) {
        size_t i = 0;
        for (; i < pos && i < sizeof(clientBanner) - 1 && buf[i] != '\n'; i++) {
            if (buf[i] != '\r') clientBanner[i] = buf[i];
        }
        clientBanner[i] = '\0';
    }

    EventLogger::logEvent("ssh", ip.c_str(), "", "", clientBanner, "connect");
    Serial.printf("[SSH] Banner from %s: %s\n", ip.c_str(), clientBanner);

    client.stop();
}
