#ifndef CONFIG_H
#define CONFIG_H

#include "proxy_server.h"

// Load configuration from .env file
// Returns 0 on success, -1 on failure
int load_config(const char *filename, proxyServerConfig_t *config);

#endif
