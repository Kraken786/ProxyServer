#ifndef TLS_PARSER_H
#define TLS_PARSER_H

#include <stddef.h>
#include <stdint.h>

// Check if buffer contains a TLS Client Hello and extract ALPN
// Returns 1 if h2 is found in ALPN, 0 otherwise
int check_tls_alpn_h2(const uint8_t *data, size_t len);

#endif
