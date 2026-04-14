#ifndef HTTP_HONEYPOT_H
#define HTTP_HONEYPOT_H

#include <ESPAsyncWebServer.h>

class HTTPHoneypot {
public:
    static void setup(AsyncWebServer& server);
};

#endif
