#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

        // Route based on the path
        const char *response;
        if (path != NULL && strcmp(path, "/") == 0) {
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
