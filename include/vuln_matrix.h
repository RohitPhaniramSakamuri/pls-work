#ifndef VULN_MATRIX_H
#define VULN_MATRIX_H

// Mirai top-100 credential pairs (public data — published in academic literature and CVE databases).
// Honeypot firmware accepts these to lure attackers into richer command-logging sessions.

static const char* MIRAI_CREDS[][2] = {
    {"root",    "xc3511"},
    {"root",    "vizxv"},
    {"root",    "888888"},
    {"admin",   "admin"},
    {"root",    "default"},
    {"root",    "root"},
    {"admin",   ""},
    {"root",    ""},
    {"root",    "12345"},
    {"admin",   "1234"},
    {"user",    "user"},
    {"admin",   "password"},
    {"root",    "pass"},
    {"root",    "1234"},
    {"root",    "54321"},
    {"support", "support"},
    {"root",    "123456"},
    {"admin",   "12345"},
    {"root",    "guest"},
    {"admin",   "smcadmin"},
    {"root",    "7ujMko0admin"},
    {"admin",   "7ujMko0admin"},
    {"root",    "system"},
    {"admin",   "system"},
    {"root",    "password"},
    {"root",    "1111"},
    {"root",    "666666"},
    {"root",    "654321"},
    {"root",    "111111"},
    {"root",    "ipc"},
    {"root",    "tlJwpbo6"},
    {"root",    "Zte521"},
    {"root",    "hi3518"},
    {"root",    "jvbzd"},
    {"root",    "anko"},
    {"root",    "zlxx."},
    {"root",    "7ujMko0vizxv"},
    {"root",    "OxhlwSG8"},
    {"root",    "abc123"},
    {"admin",   "abc123"},
    {"admin",   "123456"},
    {"admin",   "54321"},
    {"admin",   "666666"},
    {"admin",   "1111"},
    {"admin",   "pass"},
    {"admin",   "meinsm"},
    {"admin",   "admin1234"},
    {"admin",   "Admin"},
    {"admin",   "nimda"},
    {"admin",   "admin123"},
    {"admin",   "000000"},
    {"admin",   "1234567890"},
    {"admin",   "0987654321"},
    {"admin",   "supervisor"},
    {"supervisor", "supervisor"},
    {"supervisor", ""},
    {"guest",   "guest"},
    {"guest",   "12345"},
    {"guest",   ""},
    {"ubnt",    "ubnt"},
    {"default", "default"},
    {"root",    "alpine"},
    {"root",    "openelec"},
    {"root",    "raspberry"},
    {"pi",      "raspberry"},
    {"admin",   "raspberry"},
    {"root",    "nagiosxi"},
    {"admin",   "nagiosxi"},
    {"root",    "dreambox"},
    {"admin",   "dreambox"},
    {"root",    "trendnet"},
    {"admin",   "trendnet"},
    {"admin",   "epicrouter"},
    {"admin",   "conexant"},
    {"admin",   "motorola"},
    {"admin",   "comcast"},
    {"root",    "comcast"},
    {"root",    "amped"},
    {"admin",   "amped"},
    {"root",    "operator"},
    {"admin",   "operator"},
    {"root",    "tslinux"},
    {"admin",   "tslinux"},
    {"root",    "vertex25ektks"},
    {"root",    "vstarcam2015"},
    {"root",    "20150602"},
    {"admin",   "20150602"},
    {"root",    "1001chin"},
    {"admin",   "1001chin"},
    {"root",    "antslq"},
    {"root",    "realtek"},
    {"admin",   "realtek"},
    {"root",    "huigu309"},
    {"admin",   "huigu309"},
    {"root",    "cat1029"},
    {"service", "service"},
    {"service", ""},
    {"nobody",  "nobody"},
    {"nobody",  ""},
    {"mother",  "f**ker"},
    {"root",    "GM8182"},
    {"root",    "Mware1"},
    {"root",    "klv123"},
    {"root",    "klv1234"}
};

static const int MIRAI_CREDS_COUNT = (int)(sizeof(MIRAI_CREDS) / sizeof(MIRAI_CREDS[0]));

// Check if a username/password pair is in the Mirai list
inline bool isMiraiCred(const char* user, const char* pass) {
    for (int i = 0; i < MIRAI_CREDS_COUNT; i++) {
        if (strcmp(MIRAI_CREDS[i][0], user) == 0 &&
            strcmp(MIRAI_CREDS[i][1], pass) == 0) {
            return true;
        }
    }
    return false;
}

// Weak cipher config constants
#define WEAK_CIPHER_RC4    "RC4-MD5"
#define WEAK_CIPHER_DES    "DES-CBC3-SHA"
#define WEAK_CIPHER_NULL   "NULL-MD5"
#define SSH_WEAK_KEX       "diffie-hellman-group1-sha1"
#define SSH_WEAK_HOST_KEY  "ssh-dss"

#endif // VULN_MATRIX_H
