/* common.c
 * common socket routin
 *
 * Copyright 2015, Chen Wei <weichen302@gmail.com>
 *
 * License GPLv3: GNU GPL version 3
 * This is free software: you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 *
 * Please send bug reports and questions to Chen Wei <weichen302@gmail.com>
 */

#include "common.h"
#include <stdarg.h>
#include <assert.h>

static size_t strlcpy(char *dst, char *src, size_t size);
static inline size_t get_log_timestamp(char *buf, size_t bufsize);

/* connect to host:serv, return socket file descriptor, -1 on error */
int udp_connect(const char *host)
{
    int sockfd;
    int err;
    struct sockaddr_in serv;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);

    err = inet_aton(host, &(serv.sin_addr));
    if (err == 0)
        return -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    /* udp doesn't need connect. the connect here set parm to the socket fd,
     * later can simply read and write that fd
     */
    err = connect(sockfd, (struct sockaddr *)&serv, (socklen_t)sizeof(serv));
    if (err == -1) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}


int create_and_bind(struct sockaddr_in *addr, char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;  // IPV4 or IPV6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;  // wildcard IP
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    int reuse = 1;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
                     rp->ai_protocol);
        if (sfd == -1)
            continue;

        // for debug
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            // save to global var for handshake
            memset(addr, 0, sizeof(struct sockaddr_in));
            memcpy(addr, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        close(sfd);
    }


    if (rp == NULL) {
        fprintf(stderr, "could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}


int setnonblocking(int sfd)
{
    int flags;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(sfd, F_SETFL, flags) == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}


/* from UNP, return -1 on error, size readed on success */
ssize_t readn(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n;
    ssize_t nread;
    char *bufp = usrbuf;

    while (nleft > 0) {
        if ((nread = read(fd, bufp, nleft)) < 0) {
            if (errno == EINTR)
                nread = 0;
            else
                return -1;
        } else if (nread == 0)      // EOF
            break;

        nleft -= nread;
        bufp += nread;
    }

    return (n - nleft);
}

/* from UNP */
ssize_t writen(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0) {
        if ((nwritten = write(fd, bufp, nleft)) <= 0) {
            if (errno == EINTR)
                nwritten = 0;
            else
                return -1;
        }
        nleft -= nwritten;
        bufp += nwritten;
    }

    return n;
}


/* connect to host:serv, return socket file descriptor, -1 on error */
int tcp_connect(const char *host, const char *serv)
{
    int n, sockfd;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof(hints));
    //hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(n));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                 /* Success */

        close(sockfd);
    }

    if (rp == NULL) {             /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        return -1;
    }

    freeaddrinfo(res);
    return sockfd;
}

static inline size_t get_log_timestamp(char *buf, size_t bufsize)
{
    time_t now = time(NULL);
    struct tm tm_now;
    size_t len;

    tm_now = *localtime(&now);
    len = strftime(buf, bufsize, "%Y-%m-%d %H:%M:%S ", &tm_now);
    return len;
}

void log_debug(char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUFSIZE];
    char tempbuf[LOG_BUFSIZE];
    char *bp;
    int i;
    char *p, *sval;
    int ival;
    size_t tm_len;

    memset(buf, 0, sizeof(buf));
    memset(tempbuf, 0, sizeof(tempbuf));
    bp = buf;
    va_start(ap, fmt);

    tm_len = get_log_timestamp(buf, sizeof(buf));
    i = tm_len;
    for (p = fmt; *p; p++ ) {
        if (i >= (LOG_BUFSIZE - 2)) {
            static char warning[] = "... [too long, truncated]";
            i = LOG_BUFSIZE - sizeof(warning) -1;
            i += strlcpy(bp + i, warning, LOG_BUFSIZE - i);
            assert(i < LOG_BUFSIZE);
            break;
        }

        sval = tempbuf;
        if (*p != '%') {
            buf[i++] = *p;
            buf[i] = '\0';
            continue;
        }

        switch (*++p) {
        case '%':
            tempbuf[0] = '%';
            tempbuf[1] = '\0';
            break;
        case 'd':
            ival = va_arg(ap, int);
            snprintf(tempbuf, sizeof(tempbuf), "%d", ival);
            break;
        case 's':
            sval = va_arg(ap, char *);
            if (sval == NULL)
                sval = "[null]";
            break;
        default:
            snprintf(tempbuf, sizeof(tempbuf), "Bad format string: \"%s\"", fmt);
            break;
        }

        assert(i < LOG_BUFSIZE);
        i += strlcpy(bp + i, sval, LOG_BUFSIZE - i);
    }
    va_end(ap);
    assert(i < LOG_BUFSIZE);
    //i += strlcpy(bp + i, "\n", LOG_BUFSIZE -i);

    if ((i >= LOG_BUFSIZE) || buf[LOG_BUFSIZE - 1] != '\0') {
        snprintf(bp, LOG_BUFSIZE,
                "Fatal error: log_debug() sanity checks failed.\n");
    }

    if (cw_daemon->logfp != NULL) {
        fputs(buf, cw_daemon->logfp);
        fflush(cw_daemon->logfp);
    }
}

static size_t strlcpy(char *dst, char *src, size_t size)
{
    if (size > 0) {
        snprintf(dst, size, "%s", src);
        dst[size - 1] = '\0';
    }

    return strlen(src);
}
