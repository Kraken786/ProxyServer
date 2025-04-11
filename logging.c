#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_LOG_LENGTH 4096

static FILE* log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static log_level_t current_log_level = LOG_INFO;

// Convert log level to string
static const char* level_to_string(log_level_t level) {
    switch (level) {
        case LOG_DEBUG:   return "DEBUG";
        case LOG_INFO:    return "INFO";
        case LOG_WARNING: return "WARNING";
        case LOG_ERROR:   return "ERROR";
        default:          return "UNKNOWN";
    }
}

bool init_logging(const char* log_file_path) {
    if (log_file != NULL) {
        return false;  // Already initialized
    }

    log_file = fopen(log_file_path, "a");
    if (log_file == NULL) {
        return false;
    }

    // Set buffer to line buffering
    setvbuf(log_file, NULL, _IOLBF, 0);
    return true;
}

void cleanup_logging(void) {
    pthread_mutex_lock(&log_mutex);
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
    pthread_mutex_unlock(&log_mutex);
}

void set_log_level(log_level_t level) {
    pthread_mutex_lock(&log_mutex);
    current_log_level = level;
    pthread_mutex_unlock(&log_mutex);
}

void log_message(log_level_t level, const char* format, ...) {
    if (level < current_log_level || log_file == NULL) {
        return;
    }

    pthread_mutex_lock(&log_mutex);

    // Get current time
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm* tm_info = localtime(&tv.tv_sec);

    // Format timestamp
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    // Print timestamp, thread ID, and log level
    fprintf(log_file, "[%s.%03ld][%lu] ", 
            timestamp, tv.tv_usec / 1000, 
            (unsigned long)pthread_self());

    // Print the actual message
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    // Add newline if not present
    if (format[strlen(format) - 1] != '\n') {
        fprintf(log_file, "\n");
    }

    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}