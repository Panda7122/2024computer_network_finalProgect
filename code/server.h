#ifndef __SERVER_H
#define __SERVER_H
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

#include <map>
#include <string>
// #include "cJSON.h"
#define ERR_EXIT(a) \
    do {            \
        perror(a);  \
        exit(1);    \
    } while (0)
#define FILE_LEN 50
#define BUFFER_SIZE 1024
#define MAX_MSG_LEN 512
#define MAX_CLIENTS 1024
#define MAX(a, b) ((a > b) ? a : b)
#define MIN(a, b) ((a < b) ? a : b)
enum state {
    INVALID,
    NOTLOGIN,
    REGIST_ACCOUNT,
    REGIST_PASSWORD,
    LOGINING_ACCOUNT,
    LOGINING_PASSWORD,
    LOGINED,
};
typedef struct {
    char hostname[512];   // server's hostname
    unsigned short port;  // port to listen
    int listen_fd;        // fd to wait for a new connection
} server;
typedef struct {
    char host[512];                 // client's host
    int conn_fd;                    // fd to talk with client
    char client_name[MAX_MSG_LEN];  // data sent by/to client
    char buf[BUFFER_SIZE];          // data sent by/to client
    size_t buf_len;                 // bytes used by buf
    enum state status;
} request;

server svr;
int maxfd;

#endif
