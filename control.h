#ifndef CONTROL_H
#define CONTROL_H

#include "proxy_server.h"

#define CONTROL_SOCKET_PATH "/tmp/proxy_server.sock"

// Start the control server thread
int start_control_server(proxyServer_t *server);

// Send a command to the running daemon
// Returns 0 on success, -1 on failure
int send_control_command(const char *cmd);

#endif
