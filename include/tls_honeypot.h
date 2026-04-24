#ifndef TLS_HONEYPOT_H
#define TLS_HONEYPOT_H

/*
 * tls_honeypot.h — Low-interaction TLS/SSL vulnerability surface honeypot (port 443).
 *
 * Per the PDF vulnerability matrix: deliberate exposure of deprecated cipher suites
 * (SSLv2, SSLv3, TLS 1.0) and weak cipher advertisements to capture:
 *   - SSL/TLS version probing
 *   - BEAST/POODLE/DROWN scanner activity
 *   - MQTT-over-TLS scanner fingerprinting
 *   - ClientHello cipher suite enumeration
 *
 * Implementation: raw TCP on port 443. On ClientHello receipt:
 *   1. Parse offered cipher suites and TLS version from ClientHello
 *   2. Respond with TLS 1.0 ServerHello advertising RC4-SHA (weak cipher)
 *   3. Log the connection as a 'connect' event with cipher details in cmd field
 *   4. After ServerHello, read up to 512 more bytes (Certificate request etc.) and close
 *
 * This is intentionally low-interaction — we do NOT complete the TLS handshake.
 */

#include <Arduino.h>
#include <AsyncTCP.h>

class TLSHoneypot {
public:
    static void begin(uint16_t port = 443);
    static void loop();

private:
    static AsyncServer* _server;
    static void _onClient(void* arg, AsyncClient* client);
    static void _onData(void* arg, AsyncClient* client, void* data, size_t len);
    static void _onDisconnect(void* arg, AsyncClient* client);

    // TLS record types
    static constexpr uint8_t TLS_CONTENT_HANDSHAKE = 0x16;
    static constexpr uint8_t TLS_HANDSHAKE_CLIENTHELLO = 0x01;
    static constexpr uint8_t TLS_HANDSHAKE_SERVERHELLO = 0x02;

    // Weak cipher suite constants (deliberately advertised for honeypot fidelity)
    static constexpr uint16_t CIPHER_RC4_SHA          = 0x0005;  // TLS_RSA_WITH_RC4_128_SHA
    static constexpr uint16_t CIPHER_RC4_MD5          = 0x0004;  // TLS_RSA_WITH_RC4_128_MD5
    static constexpr uint16_t CIPHER_3DES_SHA         = 0x000A;  // TLS_RSA_WITH_3DES_EDE_CBC_SHA (SWEET32)
    static constexpr uint16_t CIPHER_NULL_MD5         = 0x0001;  // TLS_RSA_WITH_NULL_MD5
    static constexpr uint16_t CIPHER_EXPORT_RC4_40    = 0x0003;  // TLS_RSA_EXPORT_WITH_RC4_40_MD5

    static void _sendWeakServerHello(AsyncClient* client, uint16_t chosen_cipher);
    static uint16_t _parseCiphers(const uint8_t* buf, size_t len, char* out, size_t out_len);
    static bool _isWeakCipher(uint16_t cipher);
};

#endif // TLS_HONEYPOT_H
