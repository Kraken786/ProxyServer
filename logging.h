#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

// Log levels
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} log_level_t;

// Initialize logging system
bool init_logging(const char* log_file_path);

// Cleanup logging system
void cleanup_logging(void);

// Log message with specified level
void log_message(log_level_t level, const char* format, ...);

// Set minimum log level
void set_log_level(log_level_t level);

// Thread-safe formatted logging macros
#define LOG_DEBUG(fmt, ...) log_message(LOG_DEBUG, "[DEBUG][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_message(LOG_INFO, "[INFO][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) log_message(LOG_WARNING, "[WARNING][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_ERROR, "[ERROR][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#endif // __LOGGING_H__