#ifndef HTTP2_HANDLER_H
#define HTTP2_HANDLER_H

#include "proxy_server.h"

// Handle an HTTP/2 connection
// Takes ownership of the client socket
// initial_data: Data already read from the socket (e.g. preface)
// initial_len: Length of initial_data
void handle_http2_connection(proxyClient_t *client, const char *initial_data, size_t initial_len);

#endif
