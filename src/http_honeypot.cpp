#include "http_honeypot.h"
#include "event_logger.h"
#include "vuln_matrix.h"

static const char LOGIN_PAGE[] =
    "<!DOCTYPE html><html><head><title>NAS Login</title>"
    "<style>body{font-family:Arial;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}"
    ".box{background:#16213e;padding:40px;border-radius:8px;min-width:320px}"
    "h2{text-align:center;margin-bottom:24px}input{width:100%;padding:8px;margin:8px 0 16px;box-sizing:border-box;border-radius:4px;border:1px solid #0f3460}"
    "button{width:100%;padding:10px;background:#0f3460;color:#fff;border:none;border-radius:4px;cursor:pointer}"
    ".brand{text-align:center;font-size:0.8em;margin-top:16px;opacity:0.5}</style></head>"
    "<body><div class='box'><h2>Network Storage Device</h2>"
    "<form method='POST' action='/login'>"
    "<label>Username</label><input name='user' type='text' autocomplete='off'>"
    "<label>Password</label><input name='pass' type='password'>"
    "<button type='submit'>Login</button></form>"
    "<div class='brand'>SynoDisk DS218+ v6.2.3</div></div></body></html>";

static const char ADMIN_PAGE[] =
    "<!DOCTYPE html><html><head><title>Admin Panel</title></head>"
    "<body><h1>Device Administration</h1>"
    "<p>Firmware: 3.10.0 | Storage: 2TB | Status: Online</p>"
    "<ul><li><a href='/admin/logs'>System Logs</a></li>"
    "<li><a href='/admin/network'>Network Settings</a></li>"
    "<li><a href='/admin/users'>User Management</a></li></ul>"
    "</body></html>";

void HTTPHoneypot::begin(AsyncWebServer& server) {
    // GET / → redirect to login
    server.on("/", HTTP_GET, [](AsyncWebServerRequest* req) {
        req->redirect("/login");
    });

    // GET /login
    server.on("/login", HTTP_GET, [](AsyncWebServerRequest* req) {
        String ip = req->client()->remoteIP().toString();
        EventLogger::logEvent("http", ip.c_str(), "", "", "GET /login", "connect");
        req->send(200, "text/html", LOGIN_PAGE);
    });

    // POST /login — log credentials
    server.on("/login", HTTP_POST, [](AsyncWebServerRequest* req) {
        String ip   = req->client()->remoteIP().toString();
        String user = req->hasParam("user", true) ? req->getParam("user", true)->value() : "";
        String pass = req->hasParam("pass", true) ? req->getParam("pass", true)->value() : "";

        EventLogger::logEvent("http", ip.c_str(), user.c_str(), pass.c_str(), "POST /login", "auth_attempt");

        if (isMiraiCred(user.c_str(), pass.c_str())) {
            EventLogger::logEvent("http", ip.c_str(), user.c_str(), pass.c_str(), "POST /login", "auth_success");
            req->redirect("/admin");
        } else {
            req->send(200, "text/html",
                "<html><body><p>Invalid password</p><a href='/login'>Try again</a></body></html>");
        }
    });

    // GET /admin
    server.on("/admin", HTTP_GET, [](AsyncWebServerRequest* req) {
        String ip = req->client()->remoteIP().toString();
        EventLogger::logEvent("http", ip.c_str(), "", "", "GET /admin", "command");
        req->send(200, "text/html", ADMIN_PAGE);
    });

    // GET /cgi-bin/* — triggers exploit scanners
    server.on("/cgi-bin/", HTTP_GET, [](AsyncWebServerRequest* req) {
        String ip = req->client()->remoteIP().toString();
        EventLogger::logEvent("http", ip.c_str(), "", "", req->url().c_str(), "exploit");
        req->send(200, "text/plain", "");
    });

    // Catch-all — traversal detection + 404 logging
    server.onNotFound([](AsyncWebServerRequest* req) {
        String ip  = req->client()->remoteIP().toString();
        String url = req->url();
        if (url.indexOf("..") != -1 || url.indexOf("%2e%2e") != -1) {
            EventLogger::logEvent("http", ip.c_str(), "", "", url.c_str(), "exploit");
        } else {
            EventLogger::logEvent("http", ip.c_str(), "", "", url.c_str(), "connect");
        }
        req->send(404, "text/plain", "Not Found");
    });

    server.begin();
    Serial.println("[HTTP] Listening on port 80");
}
