#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_HEADERS 32

// Global configuration
char *g_files_directory = NULL;

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

// Helper function to check if client accepts gzip compression
int client_accepts_gzip(struct http_header *headers, int header_count) {
    const char *accept_encoding = get_header_value(headers, header_count, "Accept-Encoding");
    if (accept_encoding != NULL && strstr(accept_encoding, "gzip") != NULL) {
        return 1;
    }
    return 0;
}

// Route handlers

// Handler for /echo/{str}
const char *handle_echo(const char *echo_str, struct http_header *headers, int header_count, char *buffer, size_t buffer_size) {
    size_t echo_len = strlen(echo_str);

    if (client_accepts_gzip(headers, header_count)) {
        snprintf(buffer, buffer_size,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Encoding: gzip\r\n"
                 "Content-Length: %zu\r\n"
                 "\r\n"
                 "%s",
                 echo_len, echo_str);
        printf("Responding with 200 OK (echo: %s, gzip encoding)\n", echo_str);
    } else {
        snprintf(buffer, buffer_size,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %zu\r\n"
                 "\r\n"
                 "%s",
                 echo_len, echo_str);
        printf("Responding with 200 OK (echo: %s)\n", echo_str);
    }

    return buffer;
}

// Handler for /user-agent
const char *handle_user_agent(struct http_header *headers, int count, char *buffer, size_t buffer_size) {
    const char *user_agent = get_header_value(headers, count, "User-Agent");

    if (user_agent != NULL) {
        size_t ua_len = strlen(user_agent);

        if (client_accepts_gzip(headers, count)) {
            snprintf(buffer, buffer_size,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Encoding: gzip\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n"
                     "%s",
                     ua_len, user_agent);
            printf("Responding with 200 OK (user-agent: %s, gzip encoding)\n", user_agent);
        } else {
            snprintf(buffer, buffer_size,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n"
                     "%s",
                     ua_len, user_agent);
            printf("Responding with 200 OK (user-agent: %s)\n", user_agent);
        }

        return buffer;
    } else {
        printf("Responding with 404 Not Found (no User-Agent header)\n");
        return "HTTP/1.1 404 Not Found\r\n\r\n";
    }
}

// Handler for /
const char *handle_root() {
    printf("Responding with 200 OK\n");
    return "HTTP/1.1 200 OK\r\n\r\n";
}

// Handler for 404 Not Found
const char *handle_not_found() {
    printf("Responding with 404 Not Found\n");
    return "HTTP/1.1 404 Not Found\r\n\r\n";
}

// Handler for GET /files/{filename} - returns NULL if handled directly
const char *handle_files_get(const char *filename, int client_fd) {
    // Check if directory is configured
    if (g_files_directory == NULL) {
        printf("No files directory configured\n");
        return handle_not_found();
    }

    // Build full file path
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", g_files_directory, filename);

    // Try to open file
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        printf("File not found: %s\n", filepath);
        return handle_not_found();
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Build and send headers
    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Content-Length: %ld\r\n"
             "\r\n",
             file_size);
    send(client_fd, header, strlen(header), 0);

    // Send file contents in chunks
    char file_buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        send(client_fd, file_buffer, bytes_read, 0);
    }

    fclose(file);
    printf("Sent file: %s (%ld bytes)\n", filename, file_size);

    return NULL;  // Signal that we handled sending directly
}

// Handler for POST /files/{filename} - returns NULL if handled directly
const char *handle_files_post(const char *filename, const char *body, size_t body_len, int client_fd) {
    // Check if directory is configured
    if (g_files_directory == NULL) {
        printf("No files directory configured\n");
        return handle_not_found();
    }

    // Build full file path
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", g_files_directory, filename);

    // Open file for writing (create if doesn't exist, truncate if exists)
    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        printf("Failed to create file: %s (%s)\n", filepath, strerror(errno));
        return handle_not_found();
    }

    // Write body to file
    size_t bytes_written = fwrite(body, 1, body_len, file);
    fclose(file);

    if (bytes_written != body_len) {
        printf("Failed to write complete body to file (wrote %zu of %zu bytes)\n", bytes_written, body_len);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }

    printf("Created file: %s (%zu bytes)\n", filename, body_len);

    // Send 201 Created response
    const char *response = "HTTP/1.1 201 Created\r\n\r\n";
    send(client_fd, response, strlen(response), 0);

    return NULL;  // Signal that we handled sending directly
}

// Parse command-line arguments
void parse_arguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
            g_files_directory = argv[i + 1];
            printf("Files directory: %s\n", g_files_directory);
            i++;  // Skip the next argument since we consumed it
        }
    }
}

// Handle a client connection
void handle_client(int client_fd) {
    // Read the HTTP request
    char request[1024] = {0};
    ssize_t bytes_received = recv(client_fd, request, sizeof(request) - 1, 0);
    if (bytes_received < 0) {
        printf("Recv failed: %s\n", strerror(errno));
        close(client_fd);
        return;
    }
    request[bytes_received] = '\0';

    // Find where body starts BEFORE strtok modifies the buffer
    char *body_start_marker = strstr(request, "\r\n\r\n");
    char *body = NULL;
    if (body_start_marker != NULL) {
        body = body_start_marker + 4;  // Move past \r\n\r\n
    }

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
            *colon = '\0';  // Null-terminate the name
            headers[header_count].name = header_line;
            headers[header_count].value = colon + 2;  // Skip ": "
            header_count++;
        }
    }

    printf("Parsed %d headers\n", header_count);

    // Calculate body length from Content-Length header
    size_t body_len = 0;
    if (body != NULL) {
        const char *content_length_str = get_header_value(headers, header_count, "Content-Length");
        if (content_length_str != NULL) {
            long content_length = atol(content_length_str);
            if (content_length > 0) {
                // Calculate how much body we already have
                size_t body_bytes_in_buffer = bytes_received - (body - request);

                if (body_bytes_in_buffer >= (size_t)content_length) {
                    // All body data is already in the buffer
                    body_len = content_length;
                } else {
                    // Need to read more data
                    size_t remaining = content_length - body_bytes_in_buffer;
                    printf("Need to read %zu more bytes of body\n", remaining);
                    ssize_t additional = recv(client_fd, body + body_bytes_in_buffer, remaining, 0);
                    if (additional > 0) {
                        body_len = content_length;
                    }
                }

                if (body_len > 0) {
                    printf("Read request body: %zu bytes\n", body_len);
                }
            }
        }
    }

    // Buffer for building dynamic responses
    char response_buffer[2048];
    const char *response;

    // Route based on the path
    if (path != NULL && strncmp(path, "/files/", 7) == 0) {
        // Route based on HTTP method
        if (method != NULL && strcmp(method, "POST") == 0) {
            response = handle_files_post(path + 7, body, body_len, client_fd);
        } else if (method != NULL && strcmp(method, "GET") == 0) {
            response = handle_files_get(path + 7, client_fd);
        } else {
            response = handle_not_found();
        }

        if (response == NULL) {
            // File handler sent response directly
            close(client_fd);
            printf("Client disconnected\n");
            return;
        }
    } else if (path != NULL && strncmp(path, "/echo/", 6) == 0) {
        response = handle_echo(path + 6, headers, header_count, response_buffer, sizeof(response_buffer));
    } else if (path != NULL && strcmp(path, "/user-agent") == 0) {
        response = handle_user_agent(headers, header_count, response_buffer, sizeof(response_buffer));
    } else if (path != NULL && strcmp(path, "/") == 0) {
        response = handle_root();
    } else {
        response = handle_not_found();
    }

    // Send the response
    send(client_fd, response, strlen(response), 0);

    // Close the client connection
    close(client_fd);
    printf("Client disconnected\n");
}

int main(int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Parse command-line arguments
    parse_arguments(argc, argv);

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

    // Prevent zombie processes by ignoring SIGCHLD
    // This tells the OS to automatically reap child processes
    signal(SIGCHLD, SIG_IGN);

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

        // Fork a child process to handle this connection
        pid_t pid = fork();

        if (pid < 0) {
            // Fork failed
            printf("Fork failed: %s\n", strerror(errno));
            close(fd);
            continue;
        }

        if (pid == 0) {
            // Child process: handle the request
            close(server_fd);  // Child doesn't need the listening socket
            handle_client(fd);
            exit(0);
        }

        // Parent process: close client fd and continue accepting connections
        close(fd);
    }

    close(server_fd);

    return 0;
}
