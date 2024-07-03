#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define MAX_INPUT 256
#define MAX_RESPONSE 1024

#define GETSOCKETERRNO() (errno)
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define PORT 587

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

SOCKET connect_to_host(const char *hostname, const char *port) {
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(hostname, port, &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    printf("Remote address is:");
    char address_buffer[128];
    char service_buffer[128];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, 
                address_buffer, sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST);
    printf("%s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    SOCKET server;
    server = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(server)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    printf("Connecting...\n");
    if (connect(server, peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    freeaddrinfo(peer_address);
    printf("Connected.\n\n");
    return server;
}

void get_input(const char *prompt, char *buffer) {
    printf("%s", prompt);
    buffer[0] = 0;
    fgets(buffer, MAX_INPUT, stdin);
    const int read = strlen(buffer);
    if (read > 0) {
        buffer[read-1] = 0;
    }
}

void send_format(SOCKET server, const char *text, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, text);
    vsprintf(buffer, text, args);
    va_end(args);
    send(server, buffer, strlen(buffer), 0);
    printf("client: %s", buffer);
}

int parse_response(const char *response) {
    const char *k = response;
    if (!k[0] || !k[1] || !k[2]) return 0;
    for (; k[3]; ++k) {
        if (k == response || k[-1] == '\n') {
            if (isdigit(k[0]) && isdigit(k[1]) && isdigit(k[2])) {
                if (k[3] != '-') {
                    if (strstr(k, "\r\n")) {
                        return strtol(k, 0, 10);
                    }
                }
            }
        }
    }
    return 0;
}

void wait_on_response(SOCKET server, int expecting) {
    char response[MAX_RESPONSE+1];
    char *p = response;
    char *end = response + MAX_RESPONSE;
    int code = 0;
    while (code == 0) {
        int bytes_received = recv(server, p, end - p, 0);
        if (bytes_received < 1) {
            fprintf(stderr, "Connection dropped.\n");
            exit(1);
        }
        p += bytes_received;
        *p = 0;
        if (p == end) {
            fprintf(stderr, "Server response too large:\n");
            fprintf(stderr, "%s", response);
            exit(1);
        }
        printf("%s", response);
        code = parse_response(response);
        if (code != expecting) {
            fprintf(stderr, "Error from server (expected %d):\n", expecting);
            fprintf(stderr, "%s", response);
            exit(1);
        }
    }
    printf("Server: %s", response);
}

void send_format_ssl(SSL *ssl, const char *text, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, text);
    vsprintf(buffer, text, args);
    va_end(args);
    SSL_write(ssl, buffer, strlen(buffer));
    printf("client: %s", buffer);
}

void wait_on_response_ssl(SSL *ssl, int expecting) {
    char response[MAX_RESPONSE + 1];
    char *p = response;
    char *end = response + MAX_RESPONSE;
    int code = 0;
    while (code == 0) {
        int bytes_received = SSL_read(ssl, p, end - p);
        if (bytes_received < 1) {
            fprintf(stderr, "Connection dropped.\n");
            exit(1);
        }
        p += bytes_received;
        *p = 0;
        if (p == end) {
            fprintf(stderr, "Server response too large:\n");
            fprintf(stderr, "%s", response);
            exit(1);
        }
        printf("%s", response);
        code = parse_response(response);
        if (code != expecting) {
            fprintf(stderr, "Error from server (expected %d):\n", expecting);
            fprintf(stderr, "%s", response);
            exit(1);
        }
    }
    printf("Server: %s", response);
}

char* base64_encode(const char *input) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, strlen(input));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    return buff;
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    char hostname[MAX_INPUT];
    get_input("mail server: ", hostname);
    printf("Connecting to host: %s: %d\n", hostname, PORT);
    char snum[5];
    sprintf(snum, "%d", PORT);
    SOCKET server = connect_to_host(hostname, snum);
    wait_on_response(server, 220);

    send_format(server, "EHLO localhost\r\n");
    wait_on_response(server, 250);

    send_format(server, "STARTTLS\r\n");
    wait_on_response(server, 220);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        CLOSESOCKET(server);
        SSL_CTX_free(ctx);
        exit(1);
    }

    send_format_ssl(ssl, "EHLO localhost\r\n");
    wait_on_response_ssl(ssl, 250);

    send_format_ssl(ssl, "AUTH LOGIN\r\n");
    wait_on_response_ssl(ssl, 334);

    char username[MAX_INPUT];
    get_input("username: ", username);
    char password[MAX_INPUT];
    get_input("password: ", password);

    char *encoded_username = base64_encode(username);
    send_format_ssl(ssl, "%s\r\n", encoded_username);
    wait_on_response_ssl(ssl, 334);
    free(encoded_username);

    char *encoded_password = base64_encode(password);
    send_format_ssl(ssl, "%s\r\n", encoded_password);
    wait_on_response_ssl(ssl, 235);
    free(encoded_password);

    char sender[MAX_INPUT];
    get_input("from: ", sender);
    send_format_ssl(ssl, "MAIL FROM:<%s>\r\n", sender);
    wait_on_response_ssl(ssl, 250);

    char recipient[MAX_INPUT];
    get_input("to: ", recipient);
    send_format_ssl(ssl, "RCPT TO:<%s>\r\n", recipient);
    wait_on_response_ssl(ssl, 250);

    send_format_ssl(ssl, "DATA\r\n");
    wait_on_response_ssl(ssl, 354);

    char subject[MAX_INPUT];
    get_input("subject: ", subject);

    send_format_ssl(ssl, "From:<%s>\r\n", sender);
    send_format_ssl(ssl, "To:<%s>\r\n", recipient);
    send_format_ssl(ssl, "Subject:%s\r\n", subject);

    time_t timer;
    time(&timer);

    struct tm *timeinfo;
    timeinfo = gmtime(&timer);

    char date[128];
    strftime(date, 128, "%a, %d %b %Y %H:%M:%S +0000", timeinfo);

    send_format_ssl(ssl, "Date:%s\r\n", date);
    send_format_ssl(ssl, "\r\n");

    printf("Enter your email text, end with \".\" on a line by itself.\n");

    while (1) {
        char body[MAX_INPUT];
        get_input("> ", body);
        send_format_ssl(ssl, "%s\r\n", body);
        if (strcmp(body, ".") == 0) {
            break;
        }
    }
    
    wait_on_response_ssl(ssl, 250);
    send_format_ssl(ssl, "QUIT\r\n");
    wait_on_response_ssl(ssl, 221);
    CLOSESOCKET(server);
    SSL_shutdown(ssl); 
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("Finished.\n");
    return 0;
}
