#ifndef SSH_HONEYPOT_H
#define SSH_HONEYPOT_H

#include <WiFiServer.h>

class SSHHoneypot {
public:
    static void begin(int port);
    static void loop();
private:
    static WiFiServer* _server;
};

#endif // SSH_HONEYPOT_H
