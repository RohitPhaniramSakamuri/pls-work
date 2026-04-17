#ifndef HTTP_HONEYPOT_H
#define HTTP_HONEYPOT_H

#include <ESPAsyncWebServer.h>

class HTTPHoneypot {
public:
    static void begin(AsyncWebServer& server);
};

#endif // HTTP_HONEYPOT_H
