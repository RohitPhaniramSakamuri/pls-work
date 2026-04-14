#include "http_honeypot.h"
#include "logger.h"

void HTTPHoneypot::setup(AsyncWebServer& server) {
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        String ip = request->client()->remoteIP().toString();
        Logger::log(ip, "HTTP", "page_view", "/");
        String html = "<html><head><title>Camera Control Panel</title></head><body><h1>IoT Camera Admin Panel</h1><form action='/login' method='POST'>Username: <input name='user'><br>Password: <input type='password' name='pass'><br><input type='submit' value='Login'></form></body></html>";
        request->send(200, "text/html", html);
    });

    server.on("/login", HTTP_POST, [](AsyncWebServerRequest *request){
        String ip = request->client()->remoteIP().toString();
        String user = request->hasParam("user", true) ? request->getParam("user", true)->value() : "";
        String pass = request->hasParam("pass", true) ? request->getParam("pass", true)->value() : "";
        String payload = "{\"user\":\"" + user + "\", \"pass\":\"" + pass + "\"}";
        Logger::log(ip, "HTTP", "login_attempt", payload);
        request->send(200, "text/plain", "Login successful");
    });

    server.on("/config", HTTP_GET, [](AsyncWebServerRequest *request){
        String ip = request->client()->remoteIP().toString();
        String params = "{";
        for (size_t i = 0; i < request->params(); i++) {
            AsyncWebParameter* p = request->getParam(i);
            params += "\"" + p->name() + "\":\"" + p->value() + "\"";
            if (i < request->params() - 1) params += ",";
        }
        params += "}";
        Logger::log(ip, "HTTP", "config_access", params);
        request->send(200, "application/json", "{\"status\":\"ok\"}");
    });

    server.onNotFound([](AsyncWebServerRequest *request){
        String ip = request->client()->remoteIP().toString();
        String url = request->url();
        if (url.indexOf("../") != -1) Logger::log(ip, "HTTP", "traversal_attempt", url);
        else Logger::log(ip, "HTTP", "not_found", url);
        request->send(404, "text/plain", "Not Found");
    });
}
