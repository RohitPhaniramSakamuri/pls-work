#include "telnet_honeypot.h"
#include "event_logger.h"
#include "vuln_matrix.h"
#include <esp_random.h>

WiFiServer* TelnetHoneypot::_server = nullptr;
TelnetClient TelnetHoneypot::_clients[5];
uint8_t TelnetHoneypot::_clientCount = 0;

static const char* BUSYBOX_BANNER =
    "\r\nBusyBox v1.29.3 (2019-01-24 15:05:49 UTC) built-in shell (ash)\r\n\r\n";

static void _initCtx(SessionContext& ctx, const char* ip, const char* proto) {
    memset(&ctx, 0, sizeof(ctx));
    ctx.first_seen_ms = millis();
    ctx.last_seen_ms  = ctx.first_seen_ms;
    strncpy(ctx.src_ip, ip,    sizeof(ctx.src_ip)    - 1);
    strncpy(ctx.proto,  proto, sizeof(ctx.proto)     - 1);
    // Generate session_id
    snprintf(ctx.session_id, sizeof(ctx.session_id), "%06x", (unsigned)(esp_random() & 0xFFFFFF));
}

void TelnetHoneypot::begin(int port) {
    _server = new WiFiServer(port);
    _server->begin();
    Serial.printf("[Telnet] Listening on port %d\n", port);
}

void TelnetHoneypot::loop() {
    if (_server && _server->hasClient() && _clientCount < 5) {
        WiFiClient nc = _server->available();
        if (nc) {
            TelnetClient tc;
            tc.client = nc;
            tc.state  = STATE_LOGIN;
            tc.buffer = "";
            tc.authenticated = false;
            String ip = nc.remoteIP().toString();
            _initCtx(tc.ctx, ip.c_str(), "telnet");
            EventLogger::logEvent("telnet", ip.c_str(), "", "", "", "connect", &tc.ctx);
            nc.print(BUSYBOX_BANNER);
            nc.print("/ # login: ");
            _clients[_clientCount++] = tc;
        }
    }
    for (uint8_t i = 0; i < _clientCount; ) {
        if (!_clients[i].client.connected()) { _removeClient(i); }
        else { _handleClient(_clients[i]); i++; }
    }
}

void TelnetHoneypot::_removeClient(uint8_t idx) {
    _clients[idx].client.stop();
    for (uint8_t j = idx; j < _clientCount - 1; j++) _clients[j] = _clients[j+1];
    _clientCount--;
}

void TelnetHoneypot::_handleClient(TelnetClient& tc) {
    while (tc.client.available()) {
        char c = (char)tc.client.read();
        // Track max input length for buffer overflow detection
        if (tc.buffer.length() > tc.ctx.input_max_len)
            tc.ctx.input_max_len = (uint16_t)tc.buffer.length();

        if (c == '\r' || c == '\n') {
            String ip   = tc.client.remoteIP().toString();
            String line = tc.buffer;
            tc.buffer   = "";
            tc.ctx.last_seen_ms = millis();

            if (tc.state == STATE_LOGIN) {
                if (line.length() > 0) {
                    strncpy(tc.ctx.last_user, line.c_str(), sizeof(tc.ctx.last_user) - 1);
                    tc.client.print("Password: ");
                    tc.state = STATE_PASSWORD;
                }
            } else if (tc.state == STATE_PASSWORD) {
                strncpy(tc.ctx.last_pass, line.c_str(), sizeof(tc.ctx.last_pass) - 1);
                tc.ctx.auth_attempt_count++;
                tc.ctx.attempt_num++;
                EventLogger::logEvent("telnet", ip.c_str(),
                    tc.ctx.last_user, tc.ctx.last_pass, "", "auth_attempt", &tc.ctx);
                if (isMiraiCred(tc.ctx.last_user, tc.ctx.last_pass)) {
                    EventLogger::logEvent("telnet", ip.c_str(),
                        tc.ctx.last_user, tc.ctx.last_pass, "", "auth_success", &tc.ctx);
                    tc.client.print("\r\nWelcome!\r\n/ # ");
                    tc.state = STATE_SHELL;
                    tc.authenticated = true;
                } else {
                    delay(500);
                    tc.client.print("\r\nLogin incorrect\r\n/ # login: ");
                    tc.state = STATE_LOGIN;
                    memset(tc.ctx.last_user, 0, sizeof(tc.ctx.last_user));
                }
            } else if (tc.state == STATE_SHELL) {
                if (line.length() > 0) {
                    strncpy(tc.ctx.last_cmd, line.c_str(), sizeof(tc.ctx.last_cmd) - 1);
                    // Update download/execute flags for classifier
                    if (line.startsWith("wget ") || line.startsWith("curl "))
                        tc.ctx.downloaded_file = true;
                    if (line.startsWith("chmod "))
                        tc.ctx.chmod_seen = true;
                    if (tc.ctx.chmod_seen && line.startsWith("./"))
                        tc.ctx.executed_file = true;
                    const char* evtype = (line.startsWith("wget ") || line.startsWith("curl ") ||
                                          line.startsWith("/bin/busybox")) ? "exploit" : "command";
                    EventLogger::logEvent("telnet", ip.c_str(),
                        tc.ctx.last_user, "", line.c_str(), evtype, &tc.ctx);
                    _handleCommand(tc, line);
                }
                tc.client.print("/ # ");
            }
        } else if (isprint((unsigned char)c) && tc.buffer.length() < 256) {
            tc.buffer += c;
        }
    }
}

void TelnetHoneypot::_handleCommand(TelnetClient& tc, const String& cmd) {
    if (cmd == "uname -a") {
        tc.client.print("Linux DVR 3.10.0 #1 SMP PREEMPT armv7l GNU/Linux\r\n");
    } else if (cmd == "id" || cmd == "whoami") {
        tc.client.print("uid=0(root) gid=0(root) groups=0(root)\r\n");
    } else if (cmd == "ls" || cmd == "ls /") {
        tc.client.print("bin   dev   etc   home  lib   mnt   proc  run   sys   tmp   usr   var\r\n");
    } else if (cmd == "cat /etc/passwd") {
        tc.client.print("root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1::/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/sh\r\n");
    } else if (cmd == "cat /proc/cpuinfo") {
        tc.client.print("processor\t: 0\nvendor_id\t: ARM\nBogomips\t: 2.00\nFeatures\t: half fastmult\r\n");
    } else if (cmd == "free" || cmd == "free -m") {
        tc.client.print("             total       used       free\nMem:            62         48         14\r\n");
    } else if (cmd.startsWith("wget ") || cmd.startsWith("curl ")) {
        tc.client.print("Connecting to remote host...\r\n");
    } else if (cmd == "exit" || cmd == "logout") {
        tc.client.print("logout\r\n"); tc.client.stop();
    } else {
        tc.client.printf("sh: %s: command not found\r\n", cmd.c_str());
    }
}
