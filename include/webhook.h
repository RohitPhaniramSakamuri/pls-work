#ifndef WEBHOOK_H
#define WEBHOOK_H

#include <HTTPClient.h>

class Webhook {
public:
    static void setup(const char* url);
    static void loop();
private:
    static const char* webhook_url;
    static unsigned long last_send;
    static void sendLogs();
};

#endif
