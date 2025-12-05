#include "config.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    *(end+1) = 0;

    return str;
}

int load_config(const char *filename, proxyServerConfig_t *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_ERROR("Failed to open config file: %s", filename);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (key && value) {
            key = trim_whitespace(key);
            value = trim_whitespace(value);

            if (strcmp(key, "PORT") == 0) {
                config->port = atoi(value);
            } else if (strcmp(key, "HOST") == 0) {
                if (config->host) free(config->host);
                config->host = strdup(value);
            } else if (strcmp(key, "MAX_WORKERS") == 0) {
                config->max_workers = atoi(value);
            } else if (strcmp(key, "MAX_CONNECTIONS") == 0) {
                config->max_connections = atoi(value);
            }
        }
    }

    fclose(file);
    return 0;
}
