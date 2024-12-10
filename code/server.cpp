#include "server.h"
long long timeToUsec(struct timeval t) { return t.tv_sec * 1000000 + t.tv_usec; }

struct timeval usecToTime(long long us) {
    struct timeval t;
    t.tv_sec = us / 1000000;
    t.tv_usec = us % 1000000;
    return t;
}
std::map<std::string, SSL*> loginInfo;

char accountFile[] = "./data/account.csv";
char welcomeFlag[] = "welcome to the CSIE Chat Room\n";
const char IAC_IP[3] = "\xff\xf4";
const char* exit_msg = ">>> Client exit.\n";
const char* error_msg = ">>> Input Error.\n";
const char* createSuccess_msg = ">>> Create Account successful.\n";
const char* loginSuccess_msg = ">>> Login Account successful.\n";
const char* logout_msg = ">>> Logout, Bye Bye.\n";
const char* username_msg = "Please input your username(-1 is exit):";
const char* password_msg = "Please input your password(-1 is exit):";
const char* accountused_msg = "this account has been used, please try again\n";
const char* accountchooseMSG_msg = "which account you want to send message?\n";
const char* accountchooseFILE_msg = "which account you want to send file?\n";
const char* accountchooseAudio_msg = "which account you want to send audio?\n";
const char* accountlist_msg = "account list:\n";
const char* accountnotexist_msg = "this account is not exist, please try again\n";
const char* passwordwrong_msg = "password is incorrect, please try again\n";
const char* login_msg =
    "what option you want to choice\n"
    "1) send message\n"
    "2) send file\n"
    "3) send stream video\n"
    "4) logout\n"
    "5) exit\n"
    "your option:";
const char* notlogin_msg =
    "what option you want to choice\n"
    "1) regist a new Account\n"
    "2) login\n"
    "3) exit\n"
    "your option:";
const char* sendmessageSIG =
    "\xff"
    "[SENDMESSAGE]";

const char* getmessageSIG =
    "\xff"
    "[MESSAGE]";

const char* sendfileSIG =
    "\xff"
    "[SENDFILE]";
const char* receivefileSIG =
    "\xff"
    "[FILE]";
const char* sendaudioSIG =
    "\xff"
    "[SENDAUDIO]";
const char* receiveaudioSIG =
    "\xff"
    "[AUDIO]";
const char* splitSIG = "\xff";
SSL_CTX* ctx;

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
int initServer(unsigned short port) {
    struct sockaddr_in server_addr;
    gethostname(svr.hostname, sizeof(svr.hostname));
    svr.port = port;
    svr.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (svr.listen_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // set server's address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    // bind socket
    if (bind(svr.listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        close(svr.listen_fd);
        exit(EXIT_FAILURE);
    }

    // listening
    if (listen(svr.listen_fd, MAX_CLIENTS) == -1) {
        perror("Listen failed");
        close(svr.listen_fd);
        exit(EXIT_FAILURE);
    }

    maxfd = getdtablesize();
    dprintf(STDOUT_FILENO, "Server listening on port %d\n", port);
    return 0;
}
int accept_conn() {
    struct sockaddr_in cliaddr;
    size_t clilen;
    int conn_fd;  // fd for a new connection with client

    clilen = sizeof(cliaddr);
    conn_fd = accept(svr.listen_fd, (struct sockaddr*)&cliaddr, (socklen_t*)&clilen);
    if (conn_fd < 0) {
        if (errno == EINTR) return -2;

        if (errno == EAGAIN) return -1;  // try again
        if (errno == ENFILE) {
            (void)fprintf(stderr, "out of file descriptor table ... (maxconn %d)\n", maxfd);
            return -1;
        }
        ERR_EXIT("accept");
    }
    return conn_fd;
}
void clearBuffer(request* req) {
    memset(req->buf, 0, sizeof(req->buf));
    // req->buf[0] = '\0';
    req->buf_len = 0;
}
int handle_read(request* reqP) {
    /*  Return value:
     *      1: read successfully
     *      0: read EOF (client down)
     *     -1: read failed
     *      2: handle incomplete input
     */
    int r;
    char buf[BUFFER_SIZE * 2];
    size_t len;

    memset(buf, 0, sizeof(buf));

    // Read in request from client
    r = SSL_read(reqP->ssl, buf, sizeof(buf));
    if (r < 0) {
        // perror("read");
        return -1;
    }
    if (r == 0) return 0;
    char* p1 = strstr(buf, "\r\n");
    bool incomplete = 0;  // der
    if (p1 == NULL) {
        p1 = strstr(buf, "\n");
        if (p1 == NULL) {
            if (!strncmp(buf, IAC_IP, 2)) {  // buf[:2]==IAC_IP
                write(reqP->conn_fd, exit_msg, strlen(exit_msg));
                fprintf(stderr, "Client presses ctrl+C....\n");
                return 0;
            } else {
                // incomplete input
                incomplete = 1;
            }
        }
    }

    len = p1 - buf + 1;
    if (incomplete) {
        memmove(reqP->buf + reqP->buf_len, buf, r);
        reqP->buf_len += r;
        reqP->buf[reqP->buf_len - 1] = '\0';

        return 2;
    } else {
        memmove(reqP->buf + reqP->buf_len, buf, len);
        reqP->buf[len - 1] = '\0';
        reqP->buf_len = (len - 1);

        return 1;
    }
}

char* readline(int fd) {
    char buffer[BUFFER_SIZE];
    int cnt = 0;
    while (1) {
        int ret = read(fd, buffer + cnt, 1);

        if (ret < 0) {
            perror("Read error");
            return NULL;
        }
        if (buffer[cnt] == '\n') {
            buffer[cnt] = '\0';
            return strdup(buffer);
        }
        if (ret == 0) {
            return strdup(buffer);
        }
        cnt += ret;
    }
}

char* readline(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int cnt = 0;
    while (1) {
        int ret = SSL_read(ssl, buffer + cnt, 1);

        if (ret <= 0) {
            perror("Read error");
            return NULL;
        }
        if (buffer[cnt] == '\n') {
            buffer[cnt] = '\0';
            return strdup(buffer);
        }
        // if (ret == 0) {
        //     return strdup(buffer);
        // }
        cnt += ret;
    }
}
bool fdEOF(int fd) {
    int offset = lseek(fd, 0, SEEK_CUR);
    int end = lseek(fd, 0, SEEK_END);
    lseek(fd, offset, SEEK_SET);
    return offset == end;
}
bool haveAccount(char* fileName, char* account) {
    int fd = open(fileName, O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 0;
    }
    // Add code to read the account from the file
    while (1) {
        char* now = readline(fd);
        if (now == NULL) {
            break;
        }

        // dprintf(STDERR_FILENO, "now Line %s\n", now);
        char userName[BUFFER_SIZE];
        strcpy(userName, now);
        for (int i = 0; i < strlen(now); ++i) {
            if (userName[i] == ',') {
                userName[i] = '\0';
                break;
            }
        }
        if (strcmp(userName, account) == 0) {
            close(fd);
            return 1;
        }
        if (fdEOF(fd)) {
            free(now);
            break;
        }
        free(now);
    }

    close(fd);
    return 0;
}
bool saveAccount(char* fileName, char* account, char* password) {
    int fd = open(fileName, O_APPEND | O_WRONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 0;
    }
    char buffer[BUFFER_SIZE];
    sprintf(buffer, "%s, %s\n", account, password);
    dprintf(STDERR_FILENO, "create %s", buffer);
    write(fd, buffer, strlen(buffer));
    close(fd);
    return 1;
}
int connectAccount(char* fileName, char* account, char* password, SSL* ssl) {
    /*
        return value
        -1:error
        0:not found
        1:success
        2:wrong password
        3:used

    */
    int fd = open(fileName, O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        return -1;
    }
    // Add code to read the account from the file
    while (1) {
        char* now = readline(fd);
        if (now == NULL) {
            break;
        }

        dprintf(STDERR_FILENO, "now Line %s\n", now);
        char userName[BUFFER_SIZE];
        char nowpassword[BUFFER_SIZE];
        char fdStr[10];
        SSL* nowfd;
        strcpy(userName, now);
        for (int i = 0; i < strlen(now); ++i) {
            if (userName[i] == ',') {
                userName[i] = '\0';
                break;
            }
        }
        strcpy(nowpassword, now + strlen(userName) + 2);
        for (int i = 0; i < strlen(nowpassword); ++i) {
            if (nowpassword[i] == ',') {
                nowpassword[i] = '\0';
                break;
            }
        }
        std::string nowUser = std::string(userName);
        if (!loginInfo.count(nowUser))
            nowfd = NULL;
        else
            nowfd = loginInfo[nowUser];
        if (strcmp(userName, account) == 0) {
            if (nowfd != NULL) {
                close(fd);
                return 3;
            }
            if (strcmp(nowpassword, password) == 0) {
                loginInfo[nowUser] = ssl;
                dprintf(STDERR_FILENO, "login %s %s\n", userName, nowpassword);
                close(fd);
                return 1;
            }
            close(fd);
            return 2;
        }
        if (fdEOF(fd)) {
            free(now);
            break;
        }
        free(now);
    }

    return 0;
}
char* loginList() {
    char* ret = new char[BUFFER_SIZE];
    for (auto x : loginInfo) {
        strcat(ret, x.first.c_str());
        strcat(ret, "\n");
    }
    return ret;
}
void generateToken(unsigned char TOKEN[]) {
    for (int i = 0; i < 16; ++i) {
        TOKEN[i] = (rand() % 26) + 'A';
    }
}
void* handle_client(void* arg) {
    unsigned char TOKEN[17] = {0};
    request req;
    strcpy(req.host, svr.hostname);
    req.conn_fd = *(int*)arg;
    free(arg);
    printf("New client connected, host: %s, socketID:%d\n", req.host, req.conn_fd);
    SSL* ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, req.conn_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    req.status = INVALID;
    req.ssl = ssl;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    SSL_write(ssl, welcomeFlag, strlen(welcomeFlag));
    req.status = NOTLOGIN;
    SSL_write(ssl, notlogin_msg, strlen(notlogin_msg));
    char registAcc[BUFFER_SIZE] = {0};
    char registPWD[BUFFER_SIZE] = {0};
    SSL* nowSending = NULL;
    int cntchunk = 0;
    while (1) {
        // dprintf(STDERR_FILENO, "waiting for read...\n");
        int ret = handle_read(&req);
        // printf("ret=%d\n", ret);
        if (ret == 0) {
            SSL_write(ssl, exit_msg, strlen(exit_msg));
            dprintf(STDERR_FILENO, "lost connect from %s %d %s\n", req.host, req.buf_len, req.buf);
            break;
        }
        if (ret == 2) {
            continue;
        }
        if (ret == -1) {
            dprintf(STDERR_FILENO, "error on read\n");
            break;
        }
        printf("Received from client %s(%d): %s\n", req.host, req.conn_fd, req.buf);
        if (req.status == NOTLOGIN) {
            if (req.buf_len != 1 || req.buf[0] - '0' > 3 || req.buf[0] - '0' < 1) {
                SSL_write(ssl, error_msg, strlen(error_msg));
                SSL_write(ssl, notlogin_msg, strlen(notlogin_msg));
                clearBuffer(&req);
            }
            if (req.buf[0] - '0' == 1) {
                req.status = REGIST_ACCOUNT;
                // send REGIST ACCOUNT msg
                SSL_write(ssl, username_msg, strlen(username_msg));
                clearBuffer(&req);
            } else if (req.buf[0] - '0' == 2) {
                req.status = LOGINING_ACCOUNT;
                // send LOGIN msg
                SSL_write(ssl, username_msg, strlen(username_msg));
                clearBuffer(&req);
            } else {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                break;
            }

        } else if (req.status == LOGINING_ACCOUNT) {
            if (strcmp(req.buf, "-1") == 0) {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                break;
            }
            bool haveAcc = haveAccount(accountFile, req.buf);
            if (haveAcc) {
                strcpy(registAcc, req.buf);
                req.status = LOGINING_PASSWORD;
                SSL_write(ssl, password_msg, strlen(password_msg));
            } else {
                SSL_write(ssl, accountnotexist_msg, strlen(accountnotexist_msg));
                SSL_write(ssl, username_msg, strlen(username_msg));
            }
            clearBuffer(&req);
        } else if (req.status == LOGINING_PASSWORD) {
            if (strcmp(req.buf, "-1") == 0) {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                break;
            }
            strcpy(registPWD, req.buf);
            int connectStatus = connectAccount(accountFile, registAcc, registPWD, ssl);
            // dprintf(STDERR_FILENO, "%d\n", connectStatus);
            if (connectStatus == 0) {
                SSL_write(ssl, accountnotexist_msg, strlen(accountnotexist_msg));
                SSL_write(ssl, username_msg, strlen(username_msg));
            } else if (connectStatus == 1) {
                SSL_write(ssl, loginSuccess_msg, strlen(loginSuccess_msg));
                // SSL_write(ssl, username_msg, strlen(username_msg));
                SSL_write(ssl, login_msg, strlen(login_msg));
                strcpy(req.client_name, registAcc);
                req.status = LOGINED;
            } else if (connectStatus == 2) {
                SSL_write(ssl, passwordwrong_msg, strlen(passwordwrong_msg));
                SSL_write(ssl, password_msg, strlen(password_msg));
            } else if (connectStatus == 3) {
                SSL_write(ssl, accountused_msg, strlen(accountused_msg));
                SSL_write(ssl, username_msg, strlen(username_msg));
                req.status = LOGINING_ACCOUNT;
            }
            clearBuffer(&req);
        } else if (req.status == REGIST_ACCOUNT) {
            if (strcmp(req.buf, "-1") == 0) {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                break;
            }
            // bool haveAcc = 0;
            for (int i = 0; i < req.buf_len; ++i) {
                if (req.buf[i] == ',') {
                    SSL_write(ssl, error_msg, strlen(error_msg));
                    SSL_write(ssl, username_msg, strlen(username_msg));
                    clearBuffer(&req);
                    continue;
                }
            }
            bool haveAcc = haveAccount(accountFile, req.buf);
            if (haveAcc) {
                // this account haved been use
                SSL_write(ssl, accountused_msg, strlen(accountused_msg));
                SSL_write(ssl, username_msg, strlen(username_msg));

            } else {
                strcpy(registAcc, req.buf);
                clearBuffer(&req);
                req.status = REGIST_PASSWORD;
                SSL_write(ssl, password_msg, strlen(password_msg));
            }
            clearBuffer(&req);
        } else if (req.status == REGIST_PASSWORD) {
            if (strcmp(req.buf, "-1") == 0) {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                break;
            }
            for (int i = 0; i < req.buf_len; ++i) {
                if (req.buf[i] == ',') {
                    SSL_write(ssl, error_msg, strlen(error_msg));
                    SSL_write(ssl, password_msg, strlen(password_msg));
                    clearBuffer(&req);
                    continue;
                }
            }
            strcpy(registPWD, req.buf);
            saveAccount(accountFile, registAcc, registPWD);
            SSL_write(ssl, createSuccess_msg, strlen(createSuccess_msg));
            clearBuffer(&req);

            req.status = NOTLOGIN;
            SSL_write(ssl, notlogin_msg, strlen(notlogin_msg));
        } else if (req.status == LOGINED) {
            if (req.buf_len != 1 || req.buf[0] - '0' > 5 || req.buf[0] - '0' < 1) {
                SSL_write(ssl, error_msg, strlen(error_msg));
                SSL_write(ssl, login_msg, strlen(login_msg));
                clearBuffer(&req);
            }
            if (req.buf[0] - '0' == 1) {
                SSL_write(ssl, accountchooseMSG_msg, strlen(accountchooseMSG_msg));
                req.status = SENDMESSAGE;
                clearBuffer(&req);
            } else if (req.buf[0] - '0' == 2) {
                SSL_write(ssl, accountchooseFILE_msg, strlen(accountchooseFILE_msg));
                req.status = SENDDATA;
                clearBuffer(&req);
            } else if (req.buf[0] - '0' == 3) {
                SSL_write(ssl, accountchooseAudio_msg, strlen(accountchooseAudio_msg));
                req.status = SENDAUDIO;
                clearBuffer(&req);
            } else if (req.buf[0] - '0' == 4) {
                SSL_write(ssl, logout_msg, strlen(logout_msg));
                std::string nowUser = std::string(req.client_name);
                loginInfo.erase(nowUser);
                req.client_name[0] = '\0';
                SSL_write(ssl, notlogin_msg, strlen(notlogin_msg));
                req.status = NOTLOGIN;
                clearBuffer(&req);
            } else if (req.buf[0] - '0' == 5) {
                SSL_write(ssl, exit_msg, strlen(exit_msg));
                std::string nowUser = std::string(req.client_name);
                loginInfo.erase(nowUser);
                req.client_name[0] = '\0';
                clearBuffer(&req);
                break;
            }
        } else if (req.status == SENDMESSAGE) {
            if (loginInfo.count(std::string(req.buf))) {
                dprintf(STDERR_FILENO, "%d send to %d\n", req.conn_fd, loginInfo[std::string(req.buf)]);
                SSL_write(ssl, sendmessageSIG, strlen(sendmessageSIG));
                nowSending = loginInfo[std::string(req.buf)];
                // dprintf(STDERR_FILENO, "now sending %d\n", nowSending);
                req.status = MESSAGE;

            } else {
                char sendMsd[BUFFER_SIZE];
                sprintf(sendMsd, "%s no exist or not login\nthere is the login list %s", req.buf, loginList());
                SSL_write(ssl, sendMsd, strlen(sendMsd));
                req.status = LOGINED;
                SSL_write(ssl, login_msg, strlen(login_msg));
            }
            clearBuffer(&req);

        } else if (req.status == MESSAGE) {
            char buffer[BUFFER_SIZE];
            sprintf(buffer, "%s%s%s%s%s", getmessageSIG, req.client_name, splitSIG, req.buf, getmessageSIG);
            // |[message] req.client_name | req.buf [message]|
            dprintf(STDERR_FILENO, "sending:%s to %d\n", buffer, SSL_get_fd(nowSending));
            SSL_write(nowSending, buffer, strlen(buffer));

            req.status = LOGINED;
            SSL_write(ssl, login_msg, strlen(login_msg));
            clearBuffer(&req);
            nowSending = NULL;

        } else if (req.status == SENDDATA) {
            if (loginInfo.count(std::string(req.buf))) {
                dprintf(STDERR_FILENO, "%d send to %d\n", req.conn_fd, SSL_get_fd(loginInfo[std::string(req.buf)]));
                SSL_write(ssl, sendfileSIG, strlen(sendfileSIG));
                nowSending = loginInfo[std::string(req.buf)];
                // dprintf(STDERR_FILENO, "now sending %d\n", SSL_get_fd(nowSending));
                req.status = DATA;

                char tempBuffer[BUFFER_SIZE];
                generateToken(TOKEN);
                sprintf(tempBuffer, "%s%s", sendfileSIG, TOKEN);
                SSL_write(ssl, tempBuffer, strlen(tempBuffer));
                // dprintf(STDERR_FILENO, "sending %s\n", tempBuffer);
                cntchunk = 0;
                // dprintf(STDERR_FILENO, "now chunk:%d\n", cntchunk);
                char buffer[BUFFER_SIZE * 2];
                char fileBuffer[BUFFER_SIZE * 2];
                while (1) {
                    int lenth = SSL_read(ssl, fileBuffer, 4096 + 200);
                    // dprintf(STDERR_FILENO, "get %s(len:%ld)\n", fileBuffer, lenth);

                    if (strncmp(fileBuffer, (char*)TOKEN, 16) == 0) {
                        // SSL_write(ssl, sendfileSIG, strlen(sendfileSIG));
                        sprintf(buffer, "%s%s", receivefileSIG, req.client_name);
                        SSL_write(nowSending, buffer, strlen(buffer));
                        req.status = LOGINED;
                        SSL_write(ssl, login_msg, strlen(login_msg));
                        break;
                    } else {
                        sprintf(buffer, "%s%s%s", receivefileSIG, req.client_name, splitSIG);
                        int idx = strlen(buffer);
                        for (int i = 0; i < lenth; ++i) {
                            buffer[idx++] = fileBuffer[i];
                        }
                        for (int i = 0; i < strlen(receivefileSIG); ++i) {
                            buffer[idx++] = receivefileSIG[i];
                        }
                        SSL_write(nowSending, buffer, idx);
                        char tempBuffer[BUFFER_SIZE];
                        generateToken(TOKEN);
                        sprintf(tempBuffer, "%s%s", sendfileSIG, TOKEN);

                        // dprintf(STDERR_FILENO, "sending %s\n", tempBuffer);
                        SSL_write(ssl, tempBuffer, strlen(tempBuffer));
                        // dprintf(STDERR_FILENO, "now chunk:%d\n", cntchunk);
                        ++cntchunk;
                    }
                }
            } else {
                char sendMsd[BUFFER_SIZE];
                sprintf(sendMsd, "%s no exist or not login\nthere is the login list %s", req.buf, loginList());
                SSL_write(ssl, sendMsd, strlen(sendMsd));
                req.status = LOGINED;
                SSL_write(ssl, login_msg, strlen(login_msg));
            }
            clearBuffer(&req);
        } else if (req.status == DATA) {
        } else if (req.status == SENDAUDIO) {
            if (loginInfo.count(std::string(req.buf))) {
                dprintf(STDERR_FILENO, "%d send to %d\n", req.conn_fd, SSL_get_fd(loginInfo[std::string(req.buf)]));
                SSL_write(ssl, sendaudioSIG, strlen(sendaudioSIG));
                nowSending = loginInfo[std::string(req.buf)];
                // dprintf(STDERR_FILENO, "now sending %d\n", SSL_get_fd(nowSending));
                req.status = AUDIO;

                char tempBuffer[BUFFER_SIZE];
                generateToken(TOKEN);
                sprintf(tempBuffer, "%s%s", sendaudioSIG, TOKEN);
                SSL_write(ssl, tempBuffer, strlen(tempBuffer));
                // dprintf(STDERR_FILENO, "sending %s\n", tempBuffer);
                cntchunk = 0;
                // dprintf(STDERR_FILENO, "now chunk:%d\n", cntchunk);
                char buffer[BUFFER_SIZE * 2];
                char fileBuffer[BUFFER_SIZE * 2];
                while (1) {
                    int lenth = SSL_read(ssl, fileBuffer, 4096 + 200);
                    // dprintf(STDERR_FILENO, "get %s(len:%ld)\n", fileBuffer, lenth);

                    if (strncmp(fileBuffer, (char*)TOKEN, 16) == 0) {
                        SSL_write(nowSending, receiveaudioSIG, strlen(receiveaudioSIG));
                        req.status = LOGINED;
                        SSL_write(ssl, login_msg, strlen(login_msg));
                        break;
                    } else {
                        sprintf(buffer, "%s%s%s", receiveaudioSIG, req.client_name, splitSIG);
                        int idx = strlen(buffer);
                        for (int i = 0; i < lenth; ++i) {
                            buffer[idx++] = fileBuffer[i];
                        }
                        for (int i = 0; i < strlen(receiveaudioSIG); ++i) {
                            buffer[idx++] = receiveaudioSIG[i];
                        }
                        SSL_write(nowSending, buffer, idx);
                        char tempBuffer[BUFFER_SIZE];
                        generateToken(TOKEN);
                        sprintf(tempBuffer, "%s%s", sendaudioSIG, TOKEN);

                        // dprintf(STDERR_FILENO, "sending %s\n", tempBuffer);
                        SSL_write(ssl, tempBuffer, strlen(tempBuffer));
                        // dprintf(STDERR_FILENO, "now chunk:%d\n", cntchunk);
                        ++cntchunk;
                    }
                }
            } else {
                char sendMsd[BUFFER_SIZE];
                sprintf(sendMsd, "%s no exist or not login\nthere is the login list %s", req.buf, loginList());
                SSL_write(ssl, sendMsd, strlen(sendMsd));
                req.status = LOGINED;
                SSL_write(ssl, login_msg, strlen(login_msg));
            }
            clearBuffer(&req);
        } else if (req.status == AUDIO) {
        }
        // SSL_write(ssl, req.buf, req.buf_len);
    }

    // close connect
    if (strlen(req.client_name)) {
        loginInfo.erase(req.client_name);
    }
    req.buf[0] = '\0';
    req.buf_len = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(req.conn_fd);
    printf("Client disconnected\n");
    return NULL;
}
void sig(int num) {
    dprintf(STDERR_FILENO, "close server\n");
    close(svr.listen_fd);
    exit(num);
}
int main(int argc, char** argv) {
    srand(time(NULL));

    if (argc != 2) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        exit(1);
    }
    signal(SIGPIPE, SIG_IGN);
    SSL_library_init();
    ctx = create_context();

    configure_context(ctx);
    int conn_fd;
    initServer((unsigned short)atoi(argv[1]));
    int clientSocket;
    signal(SIGINT, sig);
    signal(SIGTERM, SIG_IGN);
    while (1) {
        int conn_fd = accept_conn();
        if (conn_fd == -2) {
            dprintf(STDERR_FILENO, "inter\n");
            break;
        }
        if (conn_fd == -1) {
            perror("Accept failed");

            continue;
        }

        pthread_t tid;
        int* new_sock = new int;
        *new_sock = conn_fd;

        if (pthread_create(&tid, NULL, handle_client, new_sock) != 0) {
            perror("Thread creation failed");
            free(new_sock);
            close(conn_fd);
        }

        // detach thread release resource
        pthread_detach(tid);
    }
    dprintf(STDERR_FILENO, "close server\n");
    close(svr.listen_fd);
}