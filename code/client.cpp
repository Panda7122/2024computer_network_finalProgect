#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
SSL_CTX *ctx;

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    /* Set the cert */
    if (SSL_CTX_load_verify_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
enum state {
    NORMAL,
    MESSAGE,
    DFILE,
    AUDIO,
};
const char sendmessageSIG[] =
    "\xff"
    "[SENDMESSAGE]";
const char sendpublickeySIG[] =
    "\xff"
    "[PUBLICKEY]";
const char getmessageSIG[] =
    "\xff"
    "[MESSAGE]";
const char *sendfileSIG =
    "\xff"
    "[SENDFILE]";
const char *receivefileSIG =
    "\xff"
    "[FILE]";
const char *sendaudioSIG =
    "\xff"
    "[SENDAUDIO]";
const char *receiveaudioSIG =
    "\xff"
    "[AUDIO]";
const char *splitSIG = "\xff";
int readline(SSL *ssl, char *Save) {
    char buffer[1024];
    int cnt = 0;
    while (1) {
        int ret = SSL_read(ssl, buffer + cnt, 1);
        // dprintf(STDERR_FILENO, "handle read cnt:%d, char:%c(%d)\n", cnt, buffer[cnt], buffer[cnt]);

        if (ret <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (buffer[cnt] == '\n') {
            // if (buffer[cnt] == '\n') buffer[cnt] = '\0';
            strncpy(Save, buffer, cnt + 1);
            // Save[cnt] = '\0';
            return cnt + 1;
        }
        cnt += ret;
    }
}

int readlineFD(int fd, char *Save) {
    char buffer[4096] = {0};
    int cnt = 0;
    while (1) {
        int ret = read(fd, buffer + cnt, 1);
        // dprintf(STDERR_FILENO, "handle read cnt:%d, char:%c(%d)\n", cnt, buffer[cnt], buffer[cnt]);

        if (ret < 0) {
            perror("Read error");
            return -1;
        }

        if (buffer[cnt] == '\n' || ret == 0) {
            // if (buffer[cnt] == '\n') buffer[cnt] = '\0';
            strncpy(Save, buffer, cnt + 1);
            // Save[cnt] = '\0';
            return cnt + 1;
        }
        cnt += ret;
        if (cnt >= 4096) {
            break;
        }
    }
    return cnt;
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
    SSL_library_init();

    ctx = create_context();

    signal(SIGPIPE, SIG_IGN);
    configure_context(ctx);
    int conn_fd;
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

    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);
    // SSL_set_tlsext_host_name(ssl, hostName); // Not needed for server-side SSL
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(clientSocket);
        exit(1);
    }
    printf("Connected to %s on port %s\n", hostName, port);
    signal(SIGTERM, SIG_IGN);
    char *bufferServer = new char[8192];
    char *bufferSTDIN = new char[8192];
    char nowPK[4096] = {0};
    char nowFileName[4096] = {0};
    enum state nowState = NORMAL;
    // send a token
    int fileFD = -1;
    int counter = 0;

    AVFormatContext *format_ctx = NULL;
    AVCodecContext *codec_ctx = NULL;
    AVPacket packet;
    AVCodec *codec;
    while (1) {
        if (errno == EINTR) {
            break;
        }
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        int maxfd = clientSocket > STDIN_FILENO ? clientSocket : STDIN_FILENO;
        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);  // io multiplexing
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }
        FILE *pipeAudio;
        if (FD_ISSET(clientSocket, &readfds)) {
            memset(bufferServer, 0, sizeof(bufferServer));
            int bytesRead = SSL_read(ssl, bufferServer, 8192);
            int error = SSL_get_error(ssl, bytesRead);
            if (bytesRead <= 0) {
                if (error == SSL_ERROR_ZERO_RETURN) {
                    printf("Server closed the connection\n");
                } else {
                    ERR_print_errors_fp(stderr);
                }
                break;
            }
            bufferServer[bytesRead] = '\0';
            if (strncmp(bufferServer, sendmessageSIG, strlen(sendmessageSIG)) == 0) {
                strcpy(nowPK, bufferServer + strlen(sendmessageSIG) + 1);
                printf("type your message(enter to send message)\n");
                nowState = MESSAGE;
            } else if (strncmp(bufferServer, sendfileSIG, strlen(sendfileSIG)) == 0) {
                // printf()
                strcpy(nowPK, bufferServer + strlen(sendfileSIG));
                if (nowState == NORMAL) {
                    printf("type your filepath:\n");
                    memset(bufferSTDIN, 0, sizeof(bufferSTDIN));
                    int ret = readlineFD(STDIN_FILENO, bufferSTDIN);
                    // printf("%d\n", ret);
                    if (ret == -1) {
                        break;
                    }
                    bufferSTDIN[ret - 1] = '\0';
                    int l = ret - 1;
                    while (bufferSTDIN[l] != '/') {
                        --l;
                    }
                    strcpy(nowFileName, bufferSTDIN + l + 1);
                    fileFD = open(bufferSTDIN, O_RDONLY);
                    if (fileFD == -1) {
                        break;
                    }
                    nowState = DFILE;
                    counter = 0;
                } else {
                    printf(">>> sending chunk...\n");
                    char chunk[4097] = {0};
                    int cnt = read(fileFD, chunk, 4096);
                    if (cnt > 0) {
                        char tempBuffer[4096 + 200] = {0};
                        sprintf(tempBuffer, "%s%s", nowFileName, splitSIG);
                        int idx = strlen(nowFileName) + 1;
                        for (int i = 0; i < cnt; ++i) {
                            tempBuffer[idx++] = chunk[i];
                        }
                        SSL_write(ssl, tempBuffer, idx);
                    } else {
                        printf(">>> end of file...\n");
                        close(fileFD);
                        printf("%s", nowPK);
                        SSL_write(ssl, nowPK, strlen(nowPK));
                        nowState = NORMAL;
                    }
                    printf("done %d\n", counter++);
                }
            } else if (strncmp(bufferServer, sendaudioSIG, strlen(sendaudioSIG)) == 0) {
                strcpy(nowPK, bufferServer + strlen(sendaudioSIG));
                if (nowState == NORMAL) {
                    printf("type your audiopath:\n");
                    memset(bufferSTDIN, 0, sizeof(bufferSTDIN));
                    int ret = readlineFD(STDIN_FILENO, bufferSTDIN);
                    if (ret == -1) {
                        break;
                    }
                    bufferSTDIN[ret - 1] = '\0';
                    int l = ret - 1;
                    while (bufferSTDIN[l] != '/') {
                        --l;
                    }
                    strcpy(nowFileName, bufferSTDIN + l + 1);
                    fileFD = open(bufferSTDIN, O_RDONLY);
                    if (fileFD == -1) {
                        break;
                    }
                    nowState = DFILE;
                    counter = 0;
                } else {
                    printf(">>> sending chunk...\n");
                    char chunk[4097] = {0};
                    int cnt = read(fileFD, chunk, 4096);
                    if (cnt > 0) {
                        char tempBuffer[4096 + 200] = {0};
                        sprintf(tempBuffer, "%s%s", nowFileName, splitSIG);
                        int idx = strlen(nowFileName) + 1;
                        for (int i = 0; i < cnt; ++i) {
                            tempBuffer[idx++] = chunk[i];
                        }
                        SSL_write(ssl, tempBuffer, idx);
                    } else {
                        printf(">>> end of file...\n");
                        close(fileFD);
                        printf("%s", nowPK);
                        SSL_write(ssl, nowPK, strlen(nowPK));
                        nowState = NORMAL;
                    }
                    printf("done %d\n", counter++);
                }
            } else if (strncmp(bufferServer, getmessageSIG, strlen(getmessageSIG)) == 0) {
                int pid;
                if ((pid = fork()) == 0) {  // child
                    bufferServer[strlen(bufferServer) - strlen(getmessageSIG)] = '\0';
                    char sender[1024];
                    char crypt_message[1024];
                    strcpy(sender, bufferServer + strlen(getmessageSIG));
                    for (int i = 0; i < strlen(sender); ++i) {
                        if (sender[i] == '\xff') {
                            sender[i] = '\0';
                            break;
                        }
                    }
                    strcpy(crypt_message, sender + strlen(sender) + 1);
                    dprintf(STDOUT_FILENO, "\u001B[?1049h");
                    //
                    dprintf(STDOUT_FILENO, "\033[36m\nthere have message from %s:\033[0m\n%s\n", sender, crypt_message);
                    dprintf(STDOUT_FILENO, "\033[0;32mplease input any char to continue\033[0m");
                    getchar();
                    fflush(stdin);
                    dprintf(STDOUT_FILENO, "\u001B[?1049l");

                    exit(0);
                } else {
                    waitpid(pid, NULL, 0);
                }
            } else if (strncmp(bufferServer, receivefileSIG, strlen(receivefileSIG)) == 0) {
                char clientName[4096] = {0};
                char fileName[4096] = {0};
                char chunk[4100] = {0};
                int now = strlen(receivefileSIG);
                int idx = 0;
                while (bufferServer[now] != *splitSIG) {
                    clientName[idx++] = bufferServer[now];
                    ++now;
                }
                ++now;
                idx = 0;
                while (bufferServer[now] != *splitSIG) {
                    fileName[idx++] = bufferServer[now];
                    ++now;
                }
                ++now;
                idx = 0;
                while (now < bytesRead - strlen(receivefileSIG)) {
                    chunk[idx++] = bufferServer[now];
                    ++now;
                }
                char saveFileName[4096] = {0};
                sprintf(saveFileName, "./save/%s_%s", clientName, fileName);
                int fd;
                if (access(saveFileName, F_OK) == 0) {
                    fd = open(saveFileName, O_WRONLY);
                    lseek(fd, 0, SEEK_END);
                } else {
                    fd = open(saveFileName, O_RDWR | O_CREAT, 0666);
                }
                write(fd, chunk, idx);
                close(fd);
            } else if (strncmp(bufferServer, receiveaudioSIG, strlen(receiveaudioSIG)) == 0) {
                char clientName[4096] = {0};
                char fileName[4096] = {0};
                char chunk[4100] = {0};
                int now = strlen(receiveaudioSIG);
                int idx = 0;
                while (bufferServer[now] != *splitSIG) {
                    clientName[idx++] = bufferServer[now];
                    ++now;
                }
                ++now;
                idx = 0;
                while (bufferServer[now] != *splitSIG) {
                    fileName[idx++] = bufferServer[now];
                    ++now;
                }
                ++now;
                idx = 0;
                while (now < bytesRead - strlen(receiveaudioSIG)) {
                    chunk[idx++] = bufferServer[now];
                    ++now;
                }
                if (nowState == NORMAL) {
                    pipeAudio = popen("aplay -", "w");
                    nowState = AUDIO;
                }
                if (idx == 0) {
                    pclose(pipeAudio);
                } else {
                    fwrite(chunk, 1, idx, pipeAudio);
                }
            } else {
                write(STDOUT_FILENO, bufferServer, bytesRead);
            }
            memset(bufferServer, 0, sizeof(bufferServer));
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(bufferSTDIN, 0, sizeof(bufferSTDIN));

            int ret = readlineFD(STDIN_FILENO, bufferSTDIN);

            if (ret == -1) {
                break;
            }
            if (nowState == MESSAGE) {
                // ssl crypt bufferSTDIN with nowPK

                nowState = NORMAL;
            }
            if (nowState == DFILE) {
                continue;
            }
            if (SSL_write(ssl, bufferSTDIN, strlen(bufferSTDIN)) <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    free(bufferServer);
    free(bufferSTDIN);
    close(clientSocket);
}