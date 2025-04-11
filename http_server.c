#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void handle_get_request(int client_socket) {
    char response[] = "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "\r\n"
                     "Hello from GET request handler!";
    send(client_socket, response, strlen(response), 0);
}

void handle_post_request(int client_socket, char* body) {
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/plain\r\n"
             "\r\n"
             "Received POST data: %s", body);
    send(client_socket, response, strlen(response), 0);
}

void handle_delete_request(int client_socket) {
    char response[] = "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "\r\n"
                     "Resource deleted successfully!";
    send(client_socket, response, strlen(response), 0);
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        // Accept connection
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        // Read request
        read(client_socket, buffer, BUFFER_SIZE);
        printf("Received request:\n%s\n", buffer);

        // Parse request method
        char *method = strtok(buffer, " ");
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) body += 4; // Skip the empty line

        // Handle different HTTP methods
        if (strcmp(method, "GET") == 0) {
            handle_get_request(client_socket);
        }
        else if (strcmp(method, "POST") == 0) {
            handle_post_request(client_socket, body);
        }
        else if (strcmp(method, "DELETE") == 0) {
            handle_delete_request(client_socket);
        }
        else {
            char response[] = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            send(client_socket, response, strlen(response), 0);
        }

        close(client_socket);
    }

    return 0;
}