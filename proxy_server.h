#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include "queue.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

#define MAX_WORKERS 10
#define MAX_CONNECTIONS 100

// Thread states
typedef enum {
    WORKER_IDLE,
    WORKER_BUSY,
    WORKER_STOPPED
} worker_state_t;

// Worker thread structure
typedef struct worker {
    pthread_t thread;
    int id;
    worker_state_t state;
    struct proxyServer *server;  // Reference to the server
} worker_t;

// Thread pool structure
typedef struct {
    pthread_mutex_t pool_mutex;
    pthread_cond_t worker_condition;
    worker_t* workers;  // Change from array to pointer
    int num_workers;
    struct proxyServer *server;  // Add server reference
} threadPool_t;

// Server configuration
typedef struct proxyServerConfig {
    char *host;
    int port;
    int max_workers;
    int max_connections;
} proxyServerConfig_t;

// Main proxy server structure
typedef struct proxyServer {
    int server_socket;
    struct sockaddr_in server_addr;
    bool is_running;
    SSL_CTX *ssl_ctx;
    char *cert_file;
    char *key_file;
    queue_t *connection_queue;
    threadPool_t *thread_pool;
    proxyServerConfig_t config;
    pthread_mutex_t server_mutex;
} proxyServer_t;

// Client connection structure
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    bool is_https;
    SSL *ssl;             // Client SSL connection
    SSL_CTX *ssl_ctx;     // Client SSL context
    SSL *remote_ssl;      // Remote server SSL connection
    SSL_CTX *remote_ctx;  // Remote server SSL context
} proxyClient_t;

// Add this structure to store client data in the queue
typedef struct {
    int socket;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
} client_data_t;

// Function prototypes

// Server initialization and management
proxyServer_t* proxy_server_create(const char* host, int port);
void proxy_server_destroy(proxyServer_t* server);
int proxy_server_start(proxyServer_t* server);
void proxy_server_stop(proxyServer_t* server);
SSL_CTX* init_ssl_ctx(const char* cert_file, const char* key_file);
proxyClient_t* create_client(void);

// Thread pool management
threadPool_t* thread_pool_create(proxyServer_t* server, int num_workers);
void thread_pool_destroy(threadPool_t* pool);
worker_t* get_available_worker(threadPool_t* pool);
void worker_mark_available(worker_t* worker);

// Connection handling
void handle_client_connection(proxyClient_t* client);
void enqueue_client_connection(proxyServer_t* server, proxyClient_t* client);
proxyClient_t* dequeue_client_connection(proxyServer_t* server);

// Worker thread functions
void* worker_thread_function(void* arg);
void process_client_request(worker_t* worker, proxyClient_t* client);

// Utility functions
int setup_server_socket(const char* host, int port);
void handle_server_error(const char* message);
bool is_server_running(proxyServer_t* server);
int connect_to_remote(proxyClient_t *client, char* host, int port);
int parse_url(const char* url, char* host, size_t host_len, int* port);
void tunnel_data(proxyClient_t *client_socket, int remote_socket);

// Add with other function prototypes
void cleanup_client_ssl(proxyClient_t* client);

#endif