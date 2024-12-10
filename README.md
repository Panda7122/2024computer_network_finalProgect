# Project Phase 2 ReadMe

## how to use

make sure your system is linux and installed `alsa-utils`

### install `alsa-utils`

1. archlinux\
`sudo pacman -S alsa-utils`
2. Debian/Ubuntu\
`sudo apt-get install alsa-utils`
3. Fedora\
`sudo dnf install alsa-utils`
4. RHEL/CentOS\
`sudo yum install alsa-utils`
5. openSUSE\
`sudo zypper install alsa-utils`

### set up server/client

`cd code` to into code envirment\
`make` to build up the server and client

`./server <port>` start server at port `<port>`

`./client <hostname/address> <port>` connect to the server at `<hostname/address>:<port>`

## server

### init server

set up the socket(listen_fd) we are listening connection with `socket(AF_INET, SOCK_STREAM, 0);`

bind listen_fd to the `<port>`

listen listen_fd with at most `MAX_CLIENTS` clients

### accept connection

I use `accept(svr.listen_fd, (struct sockaddr*)&cliaddr, (socklen_t*)&clilen);` for accept a new connection from listen_fd

connecton socket will store in conn_fd

and then create a new thread to handle this connection
(when thread run `handle_client`, it will send start massage to client)

### login system

![loginSystem](loginAutomata.png)

here is the main logic of login system

it will change state when get response from client

and send message by diffrent state

## client

get address from hostname and make clientSocket connect to `<host>:<port>`

use io multiplexing to handle clientSocket and STDIN

if client get massage from socket

put it to stdout or handle special message like file or streaming audio

if client write massage to STDIN

send it to server

### Send Message

When A wants to send a message:  

- A needs to specify the recipient (e.g., B).  
- After entering B's account,  
- A types the message and presses "Enter" to send.  
- A sends the encrypted message to B through the server.  

### Receive Message

When A receives an encrypted message:  

- It is decrypted using OpenSSL.  
- The decrypted message is displayed on the screen until A presses "Enter."  

### Send File

When A wants to send a file:  

- A needs to specify the recipient (e.g., B).  
- After entering B's account,  
- A inputs the file path.  

1. The server sends `<split char>[SENDFILE]<TOKEN>` to A.  
2. A sends the file in chunks of 4 KB each.  
3. When EOF is reached, A sends the `<TOKEN>` back to the server.  
4. otherwise A sends the encrypted file chunks to B through the server.  

This is the chunk format:  

```text
<split char>[FILE]
sender name
<split char>
file content
<split char>[FILE]
```

> `<split char>` is `0xff` in ASCII code.  

### Receive File

When A receives an encrypted file chunk:  

- It is decrypted using OpenSSL.  
- If it is the first chunk, a new file is created to save it.  
- Otherwise, the chunk is appended to the existing file.  

After all chunks are received:  

- A success message is displayed on the terminal.  
- The file is saved as `<sender_name>_<filename>`.

### Streaming Audio

#### Sender

When A wants to send audio:  

- A needs to specify the recipient (e.g., B).  
- After entering B's account,  
- A inputs the file path.  

1. The server sends `<split char>[SENDAUDIO]<TOKEN>` to A.  
2. A sends the audio in chunks of 4 KB each.  
3. When EOF is reached, A sends the `<TOKEN>` back to the server.  
4. Otherwise, A sends the encrypted audio chunks to B through the server.  

This is the chunk format:  

```text
<split char>[AUDIO]
sender name
<split char>
file content
<split char>[AUDIO]
```

> `<split char>` is `0xff` in ASCII code.  

#### Receiver

When receiving the first chunk, open a pipe for ALSA's command `aplay -`.  
> `aplay -` means playing audio through stdin.  

As A passes chunks to ALSA through the pipe:

- If A receives an empty chunk, A will close the pipe and stop playing the audio.

## encrypt & decrypt

first, use `mkcert` to make a TLS CA\
use open ssl and CA to encrypt message\
the server part:

```cpp
//initialize
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
SSL_library_init();
ctx = create_context();first, use `mkcert` to make a TLS CA\
configure_context(ctx);
// for each thread
SSL* ssl;
ssl = SSL_new(ctx);
SSL_set_fd(ssl, req.conn_fd);
if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
}
```

the client part:

```cpp
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
SSL_library_init();

ctx = create_context();

configure_context(ctx);
SSL *ssl;
ssl = SSL_new(ctx);
SSL_set_fd(ssl, clientSocket);
// SSL_set_tlsext_host_name(ssl, hostName); // Not needed for server-side SSL
if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    close(clientSocket);
    exit(1);
}
```
