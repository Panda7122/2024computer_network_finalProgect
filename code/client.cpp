#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
char *readline(int fd) {
    char buffer[1024];
    int cnt = 0;
    while (1) {
        int ret = read(fd, buffer + cnt, 1);

        if (ret < 0) {
            perror("Read error");
            return NULL;
        }
        if (buffer[cnt] == '\n' || ret == 0) {
            return strdup(buffer);
        }
        cnt += ret;
    }
}
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s [server address] [port]\n", argv[0]);
        exit(1);
    }
    int clientSocket;
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        perror("socket");
        exit(1);
    }
    char *hostName = argv[1];
    char *port = argv[2];
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostName, port, &hints, &res);
    if (status != 0) {
        dprintf(STDERR_FILENO, "getaddrinfo: %s\n", gai_strerror(status));
        close(clientSocket);
        exit(1);
    }

    if (connect(clientSocket, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(clientSocket);
        exit(1);
    }
    freeaddrinfo(res);

    printf("Connected to %s on port %s\n", hostName, port);
    signal(SIGTERM, SIG_IGN);
    char *buffer = new char[1024];
    while (1) {
        if (errno == EINTR) {
            break;
        }
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        int maxfd = clientSocket > STDIN_FILENO ? clientSocket : STDIN_FILENO;
        // dprintf(STDERR_FILENO, "I'm IN\n");
        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }

        if (FD_ISSET(clientSocket, &readfds)) {
            int bytesRead = read(clientSocket, buffer, 1024);
            if (bytesRead <= 0) {
                if (bytesRead == 0) {
                    printf("Server closed the connection\n");
                } else {
                    perror("read");
                }
                break;
            }
            write(STDOUT_FILENO, buffer, bytesRead);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            free(buffer);
            buffer = readline(STDIN_FILENO);
            if (buffer == NULL) {
                break;
            }
            // dprintf(STDERR_FILENO, "%s\n", buffer);
            send(clientSocket, buffer, strlen(buffer), 0);
        }
    }
    free(buffer);
    close(clientSocket);
}