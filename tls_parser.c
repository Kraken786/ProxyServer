#include "tls_parser.h"
#include <string.h>
#include <arpa/inet.h>

// Helper to read uint16_t from buffer (big endian)
static uint16_t read_u16(const uint8_t *data) {
    return (data[0] << 8) | data[1];
}

int check_tls_alpn_h2(const uint8_t *data, size_t len) {
    size_t pos = 0;

    // TLS Record Header
    if (len < 5) return 0;
    if (data[pos] != 0x16) return 0; // Content Type: Handshake
    pos += 5;

    // Handshake Header
    if (pos + 4 > len) return 0;
    if (data[pos] != 0x01) return 0; // Handshake Type: Client Hello
    pos += 4;

    // Client Version (2) + Random (32)
    if (pos + 34 > len) return 0;
    pos += 34;

    // Session ID
    if (pos + 1 > len) return 0;
    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return 0;
    pos += session_id_len;

    // Cipher Suites
    if (pos + 2 > len) return 0;
    uint16_t cipher_suites_len = read_u16(data + pos);
    pos += 2;
    if (pos + cipher_suites_len > len) return 0;
    pos += cipher_suites_len;

    // Compression Methods
    if (pos + 1 > len) return 0;
    uint8_t comp_methods_len = data[pos];
    pos += 1;
    if (pos + comp_methods_len > len) return 0;
    pos += comp_methods_len;

    // Extensions
    if (pos + 2 > len) return 0;
    uint16_t extensions_len = read_u16(data + pos);
    pos += 2;
    if (pos + extensions_len > len) return 0;
    
    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = read_u16(data + pos);
        uint16_t ext_len = read_u16(data + pos + 2);
        pos += 4;

        if (pos + ext_len > extensions_end) break;

        if (ext_type == 0x0010) { // ALPN Extension
            size_t alpn_pos = pos;
            if (alpn_pos + 2 <= pos + ext_len) {
                uint16_t list_len = read_u16(data + alpn_pos);
                alpn_pos += 2;
                
                size_t list_end = alpn_pos + list_len;
                while (alpn_pos + 1 <= list_end) {
                    uint8_t proto_len = data[alpn_pos];
                    alpn_pos++;
                    if (alpn_pos + proto_len > list_end) break;

                    if (proto_len == 2 && memcmp(data + alpn_pos, "h2", 2) == 0) {
                        return 1; // Found h2
                    }
                    alpn_pos += proto_len;
                }
            }
        }

        pos += ext_len;
    }

    return 0;
}
