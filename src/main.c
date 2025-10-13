#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_HEADERS 32

struct http_header {
    char *name;
    char *value;
};

// Helper function to find a header value by name (case-insensitive)
const char *get_header_value(struct http_header *headers, int count, const char *name) {
    for (int i = 0; i < count; i++) {
        if (strcasecmp(headers[i].name, name) == 0) {
            return headers[i].value;
        }
    }
    return NULL;
}

int main() {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // You can use print statements as follows for debugging, they'll be visible
    // when running tests.
    printf("Logs from your program will appear here!\n");

    int server_fd, client_addr_len;
    struct sockaddr_in client_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return 1;
    }

    // Since the tester restarts your program quite often, setting SO_REUSEADDR
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4221),
        .sin_addr = {htonl(INADDR_ANY)},
    };

    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    int connection_backlog = 5;
    if (listen(server_fd, connection_backlog) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        return 1;
    }

    printf("Waiting for clients to connect...\n");
    client_addr_len = sizeof(client_addr);

    // Accept multiple connections in a loop
    while (1) {
        int fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (fd == -1) {
            printf("Accept failed: %s\n", strerror(errno));
            continue;
        }
        printf("Client connected\n");

        // Read the HTTP request
        char request[1024] = {0};
        ssize_t bytes_received = recv(fd, request, sizeof(request) - 1, 0);
        if (bytes_received < 0) {
            printf("Recv failed: %s\n", strerror(errno));
            close(fd);
            continue;
        }
        request[bytes_received] = '\0';

        // Parse the request line to extract the path
        // Format: "METHOD PATH VERSION\r\n..."
        char *method = strtok(request, " ");
        char *path = strtok(NULL, " ");
        char *version = strtok(NULL, "\r\n");

        printf("Request: %s %s %s\n", method ? method : "", path ? path : "", version ? version : "");

        // Parse headers
        struct http_header headers[MAX_HEADERS];
        int header_count = 0;
        char *header_line;

        while ((header_line = strtok(NULL, "\r\n")) != NULL && header_count < MAX_HEADERS) {
            // Empty line marks end of headers
            if (header_line[0] == '\0') {
                break;
            }

            // Split header line into name and value at ": "
            char *colon = strstr(header_line, ": ");
            if (colon != NULL) {
                *colon = '\0'; // Null-terminate the name
                headers[header_count].name = header_line;
                headers[header_count].value = colon + 2; // Skip ": "
                header_count++;
            }
        }

        printf("Parsed %d headers\n", header_count);

        // Buffer for building dynamic responses
        char response_buffer[2048];
        const char *response;

        // Route based on the path
        if (path != NULL && strncmp(path, "/echo/", 6) == 0) {
            // Extract the string after "/echo/"
            const char *echo_str = path + 6;
            size_t echo_len = strlen(echo_str);

            // Build response with headers and body
            snprintf(response_buffer, sizeof(response_buffer),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n"
                     "%s",
                     echo_len, echo_str);
            response = response_buffer;
            printf("Responding with 200 OK (echo: %s)\n", echo_str);
        } else if (path != NULL && strcmp(path, "/user-agent") == 0) {
            // Look up User-Agent header
            const char *user_agent = get_header_value(headers, header_count, "User-Agent");

            if (user_agent != NULL) {
                size_t ua_len = strlen(user_agent);

                // Build response with headers and body
                snprintf(response_buffer, sizeof(response_buffer),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/plain\r\n"
                         "Content-Length: %zu\r\n"
                         "\r\n"
                         "%s",
                         ua_len, user_agent);
                response = response_buffer;
                printf("Responding with 200 OK (user-agent: %s)\n", user_agent);
            } else {
                response = "HTTP/1.1 404 Not Found\r\n\r\n";
                printf("Responding with 404 Not Found (no User-Agent header)\n");
            }
        } else if (path != NULL && strcmp(path, "/") == 0) {
            response = "HTTP/1.1 200 OK\r\n\r\n";
            printf("Responding with 200 OK\n");
        } else {
            response = "HTTP/1.1 404 Not Found\r\n\r\n";
            printf("Responding with 404 Not Found\n");
        }

        // Send the response
        send(fd, response, strlen(response), 0);

        // Close the client connection
        close(fd);
        printf("Client disconnected\n");
    }

    close(server_fd);

    return 0;
}
