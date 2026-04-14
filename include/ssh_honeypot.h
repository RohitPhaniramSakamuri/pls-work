#ifndef SSH_HONEYPOT_H
#define SSH_HONEYPOT_H

#include <WiFiServer.h>
#include <vector>

class SSHHoneypot {
public:
    static void setup(int port);
    static void loop();
private:
    static WiFiServer* server;
};

#endif
