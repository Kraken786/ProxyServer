#include "control.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

static void handle_control_client(int client_fd, proxyServer_t *server) {
    char buffer[256];
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        close(client_fd);
        return;
    }
    buffer[bytes_read] = '\0';

    // Remove newline if present
    char *newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';

    if (strcmp(buffer, "STATUS") == 0) {
        int active_workers = 0;
        int total_workers = server->config.max_workers;
        
        // Count active workers
        // Note: Accessing thread pool without lock for reading stats is generally okay for approximation
        // but ideally should be locked.
        if (server->thread_pool) {
            pthread_mutex_lock(&server->thread_pool->pool_mutex);
            for (int i = 0; i < server->thread_pool->num_workers; i++) {
                if (server->thread_pool->workers[i].state == WORKER_BUSY) {
                    active_workers++;
                }
            }
            pthread_mutex_unlock(&server->thread_pool->pool_mutex);
        }

        dprintf(client_fd, "Server Status: %s\n", server->is_running ? "RUNNING" : "STOPPED");
        dprintf(client_fd, "Active Workers: %d / %d\n", active_workers, total_workers);
        
    } else if (strcmp(buffer, "STATS") == 0) {
        if (server->stats) {
            stats_dump(server->stats, client_fd);
        } else {
            dprintf(client_fd, "Stats not available.\n");
        }
    } else if (strcmp(buffer, "CLEAR_STATS") == 0) {
        if (server->stats) {
            stats_clear(server->stats);
            dprintf(client_fd, "Stats cleared.\n");
        } else {
            dprintf(client_fd, "Stats not available.\n");
        }
    } else if (strcmp(buffer, "STOP") == 0) {
        dprintf(client_fd, "Stopping server...\n");
        server->is_running = false;
        // Trigger shutdown
        kill(getpid(), SIGTERM);
    } else {
        dprintf(client_fd, "Unknown command: %s\n", buffer);
    }

    close(client_fd);
}

static void *control_thread_func(void *arg) {
    proxyServer_t *server = (proxyServer_t *)arg;
    int sock_fd;
    struct sockaddr_un addr;

    // Create socket
    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOG_ERROR("Control socket error: %s", strerror(errno));
        return NULL;
    }

    // Set up address
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Unlink previous socket if it exists
    unlink(CONTROL_SOCKET_PATH);

    // Bind
    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOG_ERROR("Control bind error: %s", strerror(errno));
        close(sock_fd);
        return NULL;
    }

    // Listen
    if (listen(sock_fd, 5) == -1) {
        LOG_ERROR("Control listen error: %s", strerror(errno));
        close(sock_fd);
        return NULL;
    }

    // Allow anyone to connect (for now)
    chmod(CONTROL_SOCKET_PATH, 0666);

    LOG_INFO("Control server listening on %s", CONTROL_SOCKET_PATH);

    while (server->is_running) {
        int client_fd = accept(sock_fd, NULL, NULL);
        if (client_fd == -1) {
            if (server->is_running) {
                LOG_ERROR("Control accept error: %s", strerror(errno));
            }
            continue;
        }

        handle_control_client(client_fd, server);
    }

    close(sock_fd);
    unlink(CONTROL_SOCKET_PATH);
    return NULL;
}

int start_control_server(proxyServer_t *server) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, control_thread_func, server) != 0) {
        LOG_ERROR("Failed to create control thread");
        return -1;
    }
    pthread_detach(tid); // We don't join this thread, it runs until process exit
    return 0;
}

int send_control_command(const char *cmd) {
    int sock_fd;
    struct sockaddr_un addr;
    char buffer[4096];

    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Failed to connect to proxy server daemon. Is it running?\n");
        close(sock_fd);
        return -1;
    }

    if (write(sock_fd, cmd, strlen(cmd)) == -1) {
        perror("write");
        close(sock_fd);
        return -1;
    }

    // Read response
    ssize_t bytes_read;
    while ((bytes_read = read(sock_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }

    close(sock_fd);
    return 0;
}
