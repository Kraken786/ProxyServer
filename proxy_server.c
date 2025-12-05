#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "proxy_server.h"
#include "logging.h"

#define BUFFER_SIZE 8192
#define PORT 8080

// Add this global variable at the top of the file after includes
proxyServer_t *global_server = NULL;

// Function to free client data stored in queue
static void free_client_data(void *data)
{
    if (data)
    {
        client_data_t *client_data = (client_data_t *)data;
        free(client_data);
    }
}

// Function to print client data for debugging
static void print_client_data(void *data)
{
    if (data)
    {
        client_data_t *client_data = (client_data_t *)data;
        printf("[Socket: %d, IP: %s, Port: %d]",
               client_data->socket,
               client_data->peer_ip,
               client_data->peer_port);
    }
}

// Initialize the proxy server
proxyServer_t *proxy_server_create(proxyServerConfig_t *config)
{
    LOG_DEBUG("Creating proxy server with host: %s, port: %d", config->host, config->port);

    proxyServer_t *server = (proxyServer_t *)malloc(sizeof(proxyServer_t));
    if (!server)
    {
        LOG_ERROR("Failed to allocate server structure");
        return NULL;
    }

    // Zero out the structure
    memset(server, 0, sizeof(proxyServer_t));

    // Initialize all fields BEFORE creating thread pool
    server->config.host = strdup(config->host);
    if (!server->config.host)
    {
        LOG_ERROR("Failed to allocate host string");
        free(server);
        return NULL;
    }

    server->config.port = config->port;
    server->config.max_workers = config->max_workers;
    server->config.max_connections = config->max_connections;
    server->is_running = true;

    // Initialize connection queue first
    LOG_DEBUG("Creating connection queue with size: %d", server->config.max_connections);
    server->connection_queue = create_queue(server->config.max_connections, free_client_data, print_client_data);
    if (!server->connection_queue)
    {
        LOG_ERROR("Failed to create connection queue");
        free(server->config.host);
        free(server);
        return NULL;
    }

    // Initialize server mutex
    if (pthread_mutex_init(&server->server_mutex, NULL) != 0)
    {
        LOG_ERROR("Failed to initialize server mutex");
        delete_queue(server->connection_queue);
        thread_pool_destroy(server->thread_pool);
        free(server->config.host);
        free(server);
        return NULL;
    }

    // Initialize stats manager
    server->stats = stats_manager_create();
    if (!server->stats)
    {
        LOG_ERROR("Failed to create stats manager");
        pthread_mutex_destroy(&server->server_mutex);
        delete_queue(server->connection_queue);
        thread_pool_destroy(server->thread_pool);
        free(server->config.host);
        free(server);
        return NULL;
    }

    // Create thread pool
    LOG_DEBUG("Creating thread pool");
    server->thread_pool = thread_pool_create(server, server->config.max_workers);
    if (!server->thread_pool)
    {
        LOG_ERROR("Failed to create thread pool");
        free(server->config.host);
        free(server);
        return NULL;
    }

    // ...rest of initialization...
    return server;
}

// Initialize the thread pool
threadPool_t *thread_pool_create(proxyServer_t *server, int num_workers)
{
    if (!server)
    {
        LOG_ERROR("Invalid server parameter");
        return NULL;
    }

    threadPool_t *pool = (threadPool_t *)malloc(sizeof(threadPool_t));
    if (!pool)
    {
        LOG_ERROR("Failed to allocate thread pool");
        return NULL;
    }

    // Initialize pool BEFORE creating threads
    memset(pool, 0, sizeof(threadPool_t));
    pool->num_workers = num_workers;
    pool->server = server;

    // Initialize mutex and condition variable
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0)
    {
        LOG_ERROR("Failed to initialize pool mutex");
        free(pool);
        return NULL;
    }

    if (pthread_cond_init(&pool->worker_condition, NULL) != 0)
    {
        LOG_ERROR("Failed to initialize condition variable");
        pthread_mutex_destroy(&pool->pool_mutex);
        free(pool);
        return NULL;
    }

    // Allocate and initialize workers array
    pool->workers = (worker_t *)calloc(num_workers, sizeof(worker_t));
    if (!pool->workers)
    {
        LOG_ERROR("Failed to allocate workers array");
        pthread_mutex_destroy(&pool->pool_mutex);
        pthread_cond_destroy(&pool->worker_condition);
        free(pool);
        return NULL;
    }

    // Initialize all worker structures BEFORE creating threads
    for (int i = 0; i < num_workers; i++)
    {
        pool->workers[i].id = i;
        pool->workers[i].state = WORKER_IDLE;
        pool->workers[i].server = server;
    }

    // Store thread pool in server BEFORE creating threads
    server->thread_pool = pool;

    // Now create threads
    for (int i = 0; i < num_workers; i++)
    {
        int result = pthread_create(&pool->workers[i].thread, NULL,
                                    worker_thread_function, &pool->workers[i]);
        if (result != 0)
        {
            LOG_ERROR("Failed to create worker thread %d: %s", i, strerror(result));
            // Clean up previously created threads
            for (int j = 0; j < i; j++)
            {
                pthread_cancel(pool->workers[j].thread);
                pthread_join(pool->workers[j].thread, NULL);
            }
            free(pool->workers);
            pthread_mutex_destroy(&pool->pool_mutex);
            pthread_cond_destroy(&pool->worker_condition);
            free(pool);
            server->thread_pool = NULL;
            return NULL;
        }
        LOG_DEBUG("Created worker thread %d", i);
    }

    LOG_INFO("Thread pool created with %d workers", num_workers);
    return pool;
}

// Worker thread main function
void *worker_thread_function(void *arg)
{
    worker_t *worker = (worker_t *)arg;
    if (!worker)
    {
        LOG_ERROR("NULL worker pointer");
        return NULL;
    }
    if (!worker->server)
    {
        LOG_ERROR("NULL server pointer in worker");
        return NULL;
    }
    if (!worker->server->thread_pool)
    {
        LOG_ERROR("NULL thread pool pointer in server");
        return NULL;
    }

    proxyServer_t *server = worker->server;
    LOG_INFO("Worker thread %d started", worker->id);

    // Add mutex validity check
    if (&server->thread_pool->pool_mutex == NULL)
    {
        LOG_ERROR("Invalid mutex pointer");
        return NULL;
    }

    pthread_mutex_lock(&server->thread_pool->pool_mutex);
    worker->state = WORKER_IDLE;
    pthread_mutex_unlock(&server->thread_pool->pool_mutex);

    while (server->is_running)
    {
        pthread_mutex_lock(&server->thread_pool->pool_mutex);

        while (is_empty(server->connection_queue) && server->is_running)
        {
            LOG_DEBUG("Worker %d waiting for connection", worker->id);
            pthread_cond_wait(&server->thread_pool->worker_condition,
                              &server->thread_pool->pool_mutex);
        }

        if (!server->is_running)
        {
            pthread_mutex_unlock(&server->thread_pool->pool_mutex);
            break;
        }

        worker->state = WORKER_BUSY;
        pthread_mutex_unlock(&server->thread_pool->pool_mutex);

        proxyClient_t *client = dequeue_client_connection(server);
        if (client)
        {
            LOG_INFO("Worker %d handling connection from %s:%d",
                     worker->id, client->peer_ip, client->peer_port);

            handle_client_connection(client);
            cleanup_client_ssl(client);
            close(client->client_socket);
            free(client);

            pthread_mutex_lock(&server->thread_pool->pool_mutex);
            worker->state = WORKER_IDLE;
            pthread_mutex_unlock(&server->thread_pool->pool_mutex);
        }
    }

    LOG_INFO("Worker thread %d stopping", worker->id);
    worker->state = WORKER_STOPPED;
    return NULL;
}

// UDP Listener Thread for HTTP/3 (QUIC)
static void *udp_listener_thread(void *arg) {
    proxyServer_t *server = (proxyServer_t *)arg;
    char buffer[4096];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    LOG_INFO("UDP Listener started for HTTP/3 (QUIC) detection");

    while (server->is_running) {
        ssize_t received = recvfrom(server->udp_socket, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&client_addr, &addr_len);
        if (received > 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            
            // Log stats for QUIC packet
            if (server->stats) {
                stats_record_visit(server->stats, "UDP Packet (QUIC/HTTP3)", client_ip, "HTTP/3 (QUIC)", "Unknown");
            }
            
            LOG_DEBUG("Received UDP packet from %s:%d (Length: %ld)", client_ip, ntohs(client_addr.sin_port), received);
            
            // Since we can't parse QUIC without keys/library, we just drop it or echo it?
            // Dropping is safer.
        }
    }
    return NULL;
}

// Add new function to create a client
proxyClient_t *create_client(void)
{
    proxyClient_t *client = (proxyClient_t *)malloc(sizeof(proxyClient_t));
    if (client)
    {
        memset(client, 0, sizeof(proxyClient_t));
        client->addr_len = sizeof(client->client_addr);
        client->ssl = NULL;
        client->ssl_ctx = NULL;
        client->remote_ssl = NULL;
        client->remote_ctx = NULL;
        client->is_https = false;
        strcpy(client->peer_ip, "");
        client->peer_port = 0;
    }
    return client;
}

// Start the proxy server
int proxy_server_start(proxyServer_t *server)
{
    if (!server)
    {
        return -1;
    }

    // Initialize server socket
    server->server_socket = setup_server_socket(server->config.host, server->config.port);
    if (server->server_socket < 0)
    {
        return -1;
    }

    // Initialize UDP socket for HTTP/3
    server->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server->udp_socket >= 0) {
        struct sockaddr_in udp_addr;
        memset(&udp_addr, 0, sizeof(udp_addr));
        udp_addr.sin_family = AF_INET;
        udp_addr.sin_port = htons(server->config.port); // Same port as TCP
        udp_addr.sin_addr.s_addr = inet_addr(server->config.host);
        
        if (bind(server->udp_socket, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0) {
            LOG_ERROR("Failed to bind UDP socket: %s", strerror(errno));
            close(server->udp_socket);
            server->udp_socket = -1;
        } else {
            LOG_INFO("UDP Listener (HTTP/3) listening on %s:%d", server->config.host, server->config.port);
            
            // Start UDP thread
            pthread_t udp_tid;
            if (pthread_create(&udp_tid, NULL, udp_listener_thread, server) == 0) {
                pthread_detach(udp_tid);
            } else {
                LOG_ERROR("Failed to create UDP thread");
            }
        }
    } else {
        LOG_ERROR("Failed to create UDP socket");
    }

    LOG_INFO("Server listening on %s:%d", server->config.host, server->config.port);

    // Accept client connections
    while (server->is_running)
    {
        proxyClient_t *client = create_client();
        if (!client)
        {
            LOG_ERROR("Failed to allocate client structure");
            continue;
        }

        client->client_socket = accept(server->server_socket,
                                       (struct sockaddr *)&client->client_addr,
                                       &client->addr_len);

        if (client->client_socket < 0)
        {
            free(client);
            if (!server->is_running)
            {
                break;
            }
            LOG_ERROR("Accept failed: %s", strerror(errno));
            continue;
        }

        // Get peer information
        inet_ntop(AF_INET, &client->client_addr.sin_addr,
                  client->peer_ip, INET_ADDRSTRLEN);
        client->peer_port = ntohs(client->client_addr.sin_port);

        LOG_INFO("Accepted connection from %s:%d (socket: %d)",
                 client->peer_ip, client->peer_port, client->client_socket);

        enqueue_client_connection(server, client);
        free(client); // client data is copied to queue, can free original
    }

    return 0;
}

// Clean up resources
void proxy_server_destroy(proxyServer_t *server)
{
    if (!server)
        return;

    server->is_running = false;
    pthread_cond_broadcast(&server->thread_pool->worker_condition);

    // Wait for all workers to finish
    for (int i = 0; i < server->thread_pool->num_workers; i++)
    {
        pthread_join(server->thread_pool->workers[i].thread, NULL);
    }

    close(server->server_socket);
    if (server->udp_socket >= 0) {
        close(server->udp_socket);
    }
    thread_pool_destroy(server->thread_pool);
    delete_queue(server->connection_queue);
    pthread_mutex_destroy(&server->server_mutex);
    stats_manager_destroy(server->stats);
    free(server->config.host);

    if (server->ssl_ctx)
    {
        SSL_CTX_free(server->ssl_ctx);
    }

    ERR_free_strings();
    EVP_cleanup();

    free(server);
}

// Set up the server socket
int setup_server_socket(const char *host, int port)
{
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        handle_server_error("Failed to create socket");
        return -1;
    }

    // Enable address reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        handle_server_error("setsockopt failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        handle_server_error("Bind failed");
        return -1;
    }

    if (listen(server_socket, MAX_CONNECTIONS) < 0)
    {
        handle_server_error("Listen failed");
        return -1;
    }

    return server_socket;
}

// Handle client connection and forward requests
void cleanup_client_ssl(proxyClient_t *client)
{
    if (client->ssl)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->ssl_ctx)
    {
        SSL_CTX_free(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }
    if (client->remote_ssl)
    {
        SSL_shutdown(client->remote_ssl);
        SSL_free(client->remote_ssl);
        client->remote_ssl = NULL;
    }
    if (client->remote_ctx)
    {
        SSL_CTX_free(client->remote_ctx);
        client->remote_ctx = NULL;
    }
}

void handle_client_connection(proxyClient_t *client)
{
    char buffer[BUFFER_SIZE];
    char method[16], url[2048], protocol[16];
    char host[1024];
    int port = 80; // Default to HTTP port

    // Read the initial request
    ssize_t bytes_read = recv(client->client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0)
    {
        LOG_ERROR("Failed to read initial request");
        return;
    }
    buffer[bytes_read] = '\0';

#include "http2_handler.h"

    // Parse the request
    if (sscanf(buffer, "%15s %2047s %15s", method, url, protocol) != 3)
    {
        // Check for HTTP/2 Connection Preface
        if (strncmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
            LOG_INFO("Received HTTP/2 Connection Preface");
            handle_http2_connection(client, buffer, bytes_read);
            return;
        }

        LOG_ERROR("Failed to parse request: %.*s", (int)bytes_read, buffer);
        return;
    }

    LOG_DEBUG("Received request: %s %s %s", method, url, protocol);

    // Extract User-Agent
    char *user_agent = NULL;
    char *ua_start = strstr(buffer, "User-Agent: ");
    if (ua_start) {
        ua_start += 12; // Skip "User-Agent: "
        char *ua_end = strstr(ua_start, "\r\n");
        if (ua_end) {
            size_t ua_len = ua_end - ua_start;
            user_agent = malloc(ua_len + 1);
            if (user_agent) {
                strncpy(user_agent, ua_start, ua_len);
                user_agent[ua_len] = '\0';
            }
        }
    }

    if (global_server && global_server->stats) {
        stats_record_visit(global_server->stats, url, client->peer_ip, protocol, user_agent);
    }
    
    if (user_agent) free(user_agent);

#if 1
    // Handle CONNECT method differently
    if (strcmp(method, "CONNECT") == 0) {
        // Parse host and port from CONNECT request
        char* colon = strchr(url, ':');
        if (colon) {
            *colon = '\0';
            strncpy(host, url, sizeof(host) - 1);
            port = atoi(colon + 1);
        } else {
            strncpy(host, url, sizeof(host) - 1);
            port = 443;  // Default HTTPS port
        }

        LOG_INFO("CONNECT request to %s:%d", host, port);

        // Connect to remote server
        int remote_socket = connect_to_remote(client, host, port);
        if (remote_socket < 0) {
            const char* error_response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            send(client->client_socket, error_response, strlen(error_response), 0);
            LOG_ERROR("Failed to connect to remote server");
            return;
        }

        // Send 200 Connection Established to the client
        const char* success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (send(client->client_socket, success_response, strlen(success_response), 0) <= 0) {
            LOG_ERROR("Failed to send connection established response");
            close(remote_socket);
            return;
        }

        LOG_DEBUG("Starting CONNECT tunnel");
        tunnel_data(client, remote_socket);
        close(remote_socket);
        return;
    }
#endif

    // Parse URL and determine if it's HTTPS
    bool is_https = (strncmp(url, "https://", 8) == 0);
    if (parse_url(url, host, sizeof(host), &port) < 0)
    {
        LOG_ERROR("Failed to parse URL: %s", url);
        return;
    }

    // Set default port if not specified
    if (port == 80 && is_https)
    {
        port = 443;
    }

    LOG_INFO("Connecting to %s://%s:%d", is_https ? "https" : "http", host, port);

    // Connect to remote server
    client->is_https = is_https;
    int remote_socket = connect_to_remote(client, host, port);
    if (remote_socket < 0)
    {
        LOG_ERROR("Failed to connect to remote server");
        return;
    }

    // Modify request line to remove scheme and host for HTTP/1.1
    char *path = strchr(url + (is_https ? 8 : 7), '/');
    if (!path)
        path = "/";

    // Prepare modified request
    char modified_request[BUFFER_SIZE];
    int header_offset = 0;
    header_offset = snprintf(modified_request, sizeof(modified_request),
                             "%s %s %s\r\n", method, path, protocol);

    // Copy remaining headers, add/modify as needed
    char *headers_start = strchr(buffer, '\n') + 1;
    bool has_host = false;
    bool has_connection = false;

    // Process headers
    char *header = strtok(headers_start, "\r\n");
    while (header && (size_t)header_offset < sizeof(modified_request) - 100)
    {
        if (strncasecmp(header, "Host:", 5) == 0)
        {
            has_host = true;
            header_offset += snprintf(modified_request + header_offset,
                                      sizeof(modified_request) - header_offset,
                                      "Host: %s\r\n", host);
        }
        else if (strncasecmp(header, "Connection:", 11) == 0)
        {
            has_connection = true;
            header_offset += snprintf(modified_request + header_offset,
                                      sizeof(modified_request) - header_offset,
                                      "Connection: close\r\n");
        }
        else
        {
            header_offset += snprintf(modified_request + header_offset,
                                      sizeof(modified_request) - header_offset,
                                      "%s\r\n", header);
        }
        header = strtok(NULL, "\r\n");
    }

    // Add Host header if not present
    if (!has_host)
    {
        header_offset += snprintf(modified_request + header_offset,
                                  sizeof(modified_request) - header_offset,
                                  "Host: %s\r\n", host);
    }

    // Add Connection header if not present
    if (!has_connection)
    {
        header_offset += snprintf(modified_request + header_offset,
                                  sizeof(modified_request) - header_offset,
                                  "Connection: close\r\n");
    }

    // Add final CRLF
    header_offset += snprintf(modified_request + header_offset,
                              sizeof(modified_request) - header_offset,
                              "\r\n");

    // Forward the modified request
    if (client->is_https)
    {
        if (SSL_write(client->remote_ssl, modified_request, header_offset) <= 0)
        {
            LOG_ERROR("Failed to forward HTTPS request");
            close(remote_socket);
            return;
        }
    }
    else
    {
        if (send(remote_socket, modified_request, header_offset, 0) <= 0)
        {
            LOG_ERROR("Failed to forward HTTP request");
            close(remote_socket);
            return;
        }
    }

    LOG_DEBUG("Starting tunnel");
    tunnel_data(client, remote_socket);
    close(remote_socket);
}

// Parse URL to extract host and port
int parse_url(const char *url, char *host, size_t host_len, int *port)
{
    // Remove http:// or https:// prefix if present
    const char *host_start = url;
    if (strncmp(url, "http://", 7) == 0)
    {
        host_start = url + 7;
    }
    else if (strncmp(url, "https://", 8) == 0)
    {
        host_start = url + 8;
    }

    // Find port separator and path
    char *port_start = strchr(host_start, ':');
    char *path_start = strchr(host_start, '/');

    // Extract host
    size_t host_size;
    if (port_start && (!path_start || port_start < path_start))
    {
        host_size = (size_t)(port_start - host_start);
        *port = atoi(port_start + 1);
    }
    else
    {
        host_size = path_start ? (size_t)(path_start - host_start) : strlen(host_start);
        *port = 80; // Default to HTTP port
    }

    if (host_size >= host_len)
    {
        return -1;
    }

    strncpy(host, host_start, host_size);
    host[host_size] = '\0';

    return 0;
}

// Connect to remote server
int connect_to_remote(proxyClient_t *client, char *host, int port)
{
    struct sockaddr_in remote_addr;
    struct hostent *remote_host;

    int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket < 0)
    {
        return -1;
    }

    remote_host = gethostbyname(host);
    if (remote_host == NULL)
    {
        close(remote_socket);
        return -1;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    memcpy(&remote_addr.sin_addr, remote_host->h_addr, remote_host->h_length);

    if (connect(remote_socket, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
    {
        close(remote_socket);
        return -1;
    }

    if (client->is_https)
    {
        // Initialize SSL context for remote connection
        client->remote_ctx = SSL_CTX_new(TLS_client_method());
        if (!client->remote_ctx)
        {
            LOG_ERROR("Failed to create remote SSL context");
            close(remote_socket);
            return -1;
        }

        client->remote_ssl = SSL_new(client->remote_ctx);
        if (!client->remote_ssl)
        {
            LOG_ERROR("Failed to create remote SSL connection");
            SSL_CTX_free(client->remote_ctx);
            close(remote_socket);
            return -1;
        }

        SSL_set_fd(client->remote_ssl, remote_socket);
        if (SSL_connect(client->remote_ssl) <= 0)
        {
            LOG_ERROR("Failed to establish SSL connection with remote server");
            SSL_free(client->remote_ssl);
            SSL_CTX_free(client->remote_ctx);
            close(remote_socket);
            return -1;
        }
    }

    return remote_socket;
}

// Helper to send all data
ssize_t send_all(int socket, const char *buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        ssize_t sent = send(socket, buffer + total_sent, length - total_sent, 0);
        if (sent <= 0) return sent;
        total_sent += sent;
    }
    return total_sent;
}

#include "tls_parser.h"

// Tunnel data between client and remote server
void tunnel_data(proxyClient_t *client, int remote_socket)
{
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int client_socket = client->client_socket;
    int max_fd = (client_socket > remote_socket ? client_socket : remote_socket) + 1;
    bool first_packet = true;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(remote_socket, &read_fds);

        struct timeval tv = {30, 0};
        int ready = select(max_fd, &read_fds, NULL, NULL, &tv);

        if (ready <= 0)
        {
            if (ready < 0 && errno == EINTR)
                continue;
            break;
        }

        // Handle client -> remote
        if (FD_ISSET(client_socket, &read_fds))
        {
            ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
                break;

            // Check for TLS Client Hello and ALPN h2
            if (first_packet && !client->is_https) { // Only check for blind tunnels (CONNECT)
                if (check_tls_alpn_h2((uint8_t*)buffer, bytes_read)) {
                    LOG_INFO("Detected HTTP/2 (h2) in TLS Client Hello");
                    if (global_server && global_server->stats) {
                        // We need to update the existing entry or add a new one.
                        // stats_record_visit adds a new one if not found, or increments.
                        // Since we already recorded "CONNECT ...", this might add a duplicate or update.
                        // But we don't have the URL here easily (it was in handle_client_connection).
                        // However, we can log it as a special event or try to update.
                        // Let's just log it with the IP.
                        stats_record_visit(global_server->stats, "HTTPS Tunnel (H2 Negotiated)", client->peer_ip, "HTTP/2.0 (Tunnel)", "Unknown");
                    }
                }
                first_packet = false;
            }

            ssize_t bytes_sent;
            if (client->is_https)
            {
                bytes_sent = SSL_write(client->remote_ssl, buffer, bytes_read);
            }
            else
            {
                bytes_sent = send_all(remote_socket, buffer, bytes_read);
            }
            if (bytes_sent <= 0)
                break;
        }

        // Handle remote -> client
        if (FD_ISSET(remote_socket, &read_fds))
        {
            ssize_t bytes_read;
            if (client->is_https)
            {
                bytes_read = SSL_read(client->remote_ssl, buffer, sizeof(buffer));
            }
            else
            {
                bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0);
            }
            if (bytes_read <= 0)
                break;

            if (send_all(client_socket, buffer, bytes_read) <= 0)
                break;
        }
    }
}

// Handle server errors
void handle_server_error(const char *message)
{
    perror(message);
}

// Thread pool cleanup
void thread_pool_destroy(threadPool_t *pool)
{
    if (!pool)
        return;

    if (pool->workers)
    {
        free(pool->workers);
    }
    pthread_mutex_destroy(&pool->pool_mutex);
    pthread_cond_destroy(&pool->worker_condition);
    free(pool);
}

// Queue operations for client connections
void enqueue_client_connection(proxyServer_t *server, proxyClient_t *client)
{
    if (!server || !server->connection_queue || !client)
    {
        if (!server)
        {
            LOG_ERROR("Invalid server parameter in enqueue_client_connection");
        }
        else if (!server->connection_queue)
        {
            LOG_ERROR("Invalid connection queue in enqueue_client_connection");
        }
        else
        {
            LOG_ERROR("Invalid client parameter in enqueue_client_connection");
        }
        LOG_ERROR("Invalid parameters in enqueue_client_connection");
        return;
    }

    pthread_mutex_lock(&server->thread_pool->pool_mutex);

    if (!is_full(server->connection_queue))
    {
        client_data_t *client_data = malloc(sizeof(client_data_t));
        if (!client_data)
        {
            LOG_ERROR("Failed to allocate client data");
            pthread_mutex_unlock(&server->thread_pool->pool_mutex);
            return;
        }

        client_data->socket = client->client_socket;
        strncpy(client_data->peer_ip, client->peer_ip, INET_ADDRSTRLEN);
        client_data->peer_port = client->peer_port;

        LOG_DEBUG("Enqueueing connection from %s:%d (socket: %d)",
                  client_data->peer_ip, client_data->peer_port, client_data->socket);

        enqueue(server->connection_queue, client_data);

        // Signal waiting worker threads
        pthread_cond_broadcast(&server->thread_pool->worker_condition);
        LOG_DEBUG("Queue size after enqueue: %d", server->connection_queue->queue_size);
    }
    else
    {
        LOG_ERROR("Queue is full, connection dropped");
    }

    pthread_mutex_unlock(&server->thread_pool->pool_mutex);
}

proxyClient_t *dequeue_client_connection(proxyServer_t *server)
{
    if (!server || !server->connection_queue)
    {
        LOG_ERROR("Invalid server or queue in dequeue_client_connection");
        return NULL;
    }

    pthread_mutex_lock(&server->thread_pool->pool_mutex);

    if (is_empty(server->connection_queue))
    {
        LOG_DEBUG("Connection queue is empty");
        pthread_mutex_unlock(&server->thread_pool->pool_mutex);
        return NULL;
    }

    client_data_t *client_data = (client_data_t *)dequeue(server->connection_queue);
    if (!client_data)
    {
        LOG_ERROR("Failed to dequeue client data");
        pthread_mutex_unlock(&server->thread_pool->pool_mutex);
        return NULL;
    }

    proxyClient_t *client = create_client();
    if (!client)
    {
        LOG_ERROR("Failed to create client structure");
        free(client_data);
        pthread_mutex_unlock(&server->thread_pool->pool_mutex);
        return NULL;
    }

    client->client_socket = client_data->socket;
    strncpy(client->peer_ip, client_data->peer_ip, INET_ADDRSTRLEN);
    client->peer_port = client_data->peer_port;

    LOG_DEBUG("Dequeued connection from %s:%d (socket: %d)",
              client->peer_ip, client->peer_port, client->client_socket);

    free(client_data);

    pthread_mutex_unlock(&server->thread_pool->pool_mutex);
    return client;
}

// Update the signal handler implementation
void handle_signal(int sig)
{
    if (sig == SIGUSR1) {
        if (global_server && global_server->stats) {
            stats_print(global_server->stats);
        }
        return;
    }

    printf("\nReceived signal %d, shutting down server...\n", sig);

    if (global_server)
    {
        // Stop the server gracefully
        global_server->is_running = false;

        // Wake up all worker threads
        pthread_cond_broadcast(&global_server->thread_pool->worker_condition);

        // Close the server socket to stop accepting new connections
        if (global_server->server_socket > 0)
        {
            close(global_server->server_socket);
        }

        // Cleanup resources
        proxy_server_destroy(global_server);
        global_server = NULL;
    }

    exit(EXIT_SUCCESS);
}

// Add new function for SSL initialization
SSL_CTX *init_ssl_ctx(const char *cert_file, const char *key_file)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        LOG_ERROR("Failed to create SSL context");
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        LOG_ERROR("Failed to load certificate file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        LOG_ERROR("Failed to load private key file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

#include "control.h"

// Daemonize the process
static void daemonize() {
    pid_t pid;

    // Fork off the parent process
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // On success: The child process becomes session leader
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    // Catch, ignore and handle signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // Set new file permissions
    umask(0);

    // Change the working directory to the root directory
    // or another appropriated directory
    // chdir("/"); // Keeping current directory for now to keep log file in place

    // Close all open file descriptors
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
    {
        close(x);
    }

    // Open the log file
    // Re-initialize logging since we closed FDs
    // Note: init_logging opens a file, so we need to make sure we don't close it immediately after
    // But since we closed ALL FDs, we need to reopen stdin/out/err to /dev/null
    
    int fd0 = open("/dev/null", O_RDWR);
    int fd1 = dup(0);
    int fd2 = dup(0);
    
    (void)fd0; (void)fd1; (void)fd2; // Suppress unused warnings
}

// Update the main function to set the global server variable
int main(int argc, char *argv[])
{
    // Handle command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "status") == 0) {
            return send_control_command("STATUS");
        } else if (strcmp(argv[1], "stats") == 0) {
            return send_control_command("STATS");
        } else if (strcmp(argv[1], "clear-stats") == 0) {
            return send_control_command("CLEAR_STATS");
        } else if (strcmp(argv[1], "stop") == 0) {
            return send_control_command("STOP");
        } else if (strcmp(argv[1], "start") != 0) {
            printf("Usage: %s [start|status|stats|clear-stats|stop]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Daemonize
    daemonize();

    // Initialize logging first
    if (!init_logging("proxy_server.log"))
    {
        // Can't print to stderr since we daemonized and closed it
        return EXIT_FAILURE;
    }

    set_log_level(LOG_DEBUG);
    LOG_DEBUG("Starting proxy server initialization");

    // Set up signal handling
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to prevent crash on broken pipe
    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR ||
        signal(SIGUSR1, handle_signal) == SIG_ERR)
    {
        LOG_ERROR("Failed to set up signal handlers");
        cleanup_logging();
        return EXIT_FAILURE;
    }

#include "config.h"

    // Initialize OpenSSL globally
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Load configuration
    proxyServerConfig_t config = {0};
    // Set defaults
    config.port = PORT;
    config.host = strdup("0.0.0.0");
    config.max_workers = MAX_WORKERS;
    config.max_connections = MAX_CONNECTIONS;

    if (load_config(".env", &config) == 0) {
        LOG_INFO("Loaded configuration from .env");
    } else {
        LOG_WARNING("Failed to load .env, using defaults");
    }

    // Create proxy server with careful error checking
    proxyServer_t *proxy_server = NULL;
    LOG_DEBUG("Creating proxy server instance");

    proxy_server = proxy_server_create(&config);
    if (!proxy_server)
    {
        LOG_ERROR("Failed to create proxy server");
        free(config.host);
        cleanup_logging();
        return EXIT_FAILURE;
    }
    
    free(config.host); // We don't need this copy anymore as create makes its own copy

    LOG_DEBUG("Proxy server created successfully");
    global_server = proxy_server;

    // Start control server
    if (start_control_server(proxy_server) != 0) {
        LOG_ERROR("Failed to start control server");
        proxy_server_destroy(proxy_server);
        cleanup_logging();
        return EXIT_FAILURE;
    }

    // Start the server with error checking
    LOG_DEBUG("Starting proxy server");
    int result = proxy_server_start(proxy_server);

    if (result < 0)
    {
        LOG_ERROR("Server failed to start");
        proxy_server_destroy(proxy_server);
        cleanup_logging();
        return EXIT_FAILURE;
    }

    cleanup_logging();
    return EXIT_SUCCESS;
}