/* socks5.c
 *
 * single process, single thread, I/O event driven SOCKS5 server
 *
 * RFC1928
 *
 * Copyright 2015, Chen Wei <weichen302@gmail.com>
 *
 * License GPLv3: GNU GPL version 3
 * This is free software: you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 *
 * Please send bug reports and questions to Chen Wei <weichen302@gmail.com>
 */


#include "dns.h"
#include "socks5.h"
#include "utils.c"

/* 64 is not small, will increase in run time if necessary */
#define INIT_MAX_EVENTS  64
#define MAX_DOMAINNAME 256
#define CLIENT_CTX_SIZE  4096
#define DNS_CTX_SIZE     1024

extern int epfd;

struct sockaddr_in SERV_BIND_ADDR;
struct client_ctx *cli_rmt_fds[CLIENT_CTX_SIZE];
struct client_ctx *dns_rmt_fds[DNS_CTX_SIZE];

// prototypes
static inline void memcpy_lower(void *dst, void *src, size_t len);
void read_wire(int sfd, struct epoll_event *ev, struct client_ctx *cli);
void write_wire(int sfd, struct epoll_event *ev, struct client_ctx *cli);
void epoll_errhup(int fd);

void socks_hs_hello_1(struct client_ctx *ctx);
void  socks_hs_hello_1_reply(struct client_ctx *ctx);
void socks_hs_hello_2(struct client_ctx *ctx);
int socks_hs_hello_2_getrmtaddr(struct client_ctx *cli, struct addrinfo **res);
void socks_hs_hello_2_wakeupdns(struct client_ctx *dnsctx);
int  socks_hs_hello_2_nonbconnrmt(int rfd, struct addrinfo *result);
int  socks_hs_hello_2_rmtconn_verify(struct client_ctx *cli);
int  socks_hs_hello_2_reply(struct client_ctx *cli);


void socks5_server(struct epoll_event *ev);

void init_client_ctx(void);
struct client_ctx *lookup_ctx(struct client_ctx *ctx[], int ctxsize, int fd);
#define lookup_cli_ctx(fd) lookup_ctx(cli_rmt_fds, CLIENT_CTX_SIZE, fd)
#define lookup_dns_ctx(fd) lookup_ctx(dns_rmt_fds, DNS_CTX_SIZE, fd)

void install_ctx(struct client_ctx *ctx[], int ctxsize, struct client_ctx *cli);
void create_install_client_ctx(int clientfd, int remotefd);
void uninstall_ctx(struct client_ctx *ctx[], int ctxsize,
                   struct client_ctx *cli);
#define uninstall_cli_ctx(ctx) free(ctx->hs_in); \
                               free(ctx->hs_out); \
                               uninstall_ctx(cli_rmt_fds, CLIENT_CTX_SIZE, ctx)
#define uninstall_dns_ctx(ctx) free(ctx->fqdn); \
                               uninstall_ctx(dns_rmt_fds, DNS_CTX_SIZE, ctx)

cw_inline void clear_handshake_buf(struct handshake_buffer *buf);
cw_inline void epoll_ctl_wrap(int fd, int op, int type);

/* epoll_ctl needs too many sentences */
cw_inline void epoll_ctl_wrap(int fd, int op, int type)
{
    struct epoll_event ev;

    ev.events = type;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, op, ev.data.fd, &ev) == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}


void init_client_ctx(void)
{
    int i;

    for (i = 0; i < CLIENT_CTX_SIZE; i++)
        cli_rmt_fds[i] = NULL;

    for (i = 0; i < DNS_CTX_SIZE; i++)
        dns_rmt_fds[i] = NULL;
}

struct client_ctx *lookup_ctx(struct client_ctx *ctx[], int ctxsize, int fd)
{
    struct client_ctx *np;

    for (np = ctx[fd % ctxsize]; np != NULL; np = np->next) {
        if (np->client_fd == fd)
            return np;
        else if (np->remote_fd == fd)
            return np;
    }

    return NULL;
}


/* install remote and client fd to hash table */
void install_ctx(struct client_ctx *ctx[], int ctxsize, struct client_ctx *cli)
{
    struct client_ctx *np;
    int fd, idx;

    fd = cli->client_fd;
    idx = fd % ctxsize;
    np = ctx[idx];
    if (np == NULL) {
        ctx[idx] = cli;
    } else {
        cli->next = np;
        ctx[idx] = cli;
    }

    // now the remote fd
    fd = cli->remote_fd;
    idx = fd % ctxsize;
    np = ctx[idx];
    if (np == NULL) {
        ctx[idx] = cli;
    } else {
        cli->next = np;
        ctx[idx] = cli;
    }
}


void uninstall_ctx(struct client_ctx *ctx[], int ctxsize,
                      struct client_ctx *cli)
{
    struct client_ctx *np, *tmp;
    int cfd, rfd, idx;

    cfd = cli->client_fd;
    rfd = cli->remote_fd;

    idx = cfd % ctxsize;
    np = ctx[idx];
    tmp = NULL;
    for ( ; np != NULL; tmp = np, np = np->next) {
        if (np->client_fd == cfd)
            break;
    }

    if (tmp == NULL) {
        ctx[idx] = np->next;
    } else {
        tmp->next = np->next;
    }

    idx = rfd % ctxsize;
    np = ctx[idx];
    tmp = NULL;
    for ( ; np != NULL; tmp = np, np = np->next) {
        if (np->remote_fd == rfd)
            break;
    }

    if (tmp == NULL) {
        ctx[idx] = np->next;
    } else {
        tmp->next = np->next;
    }

    free(cli);
}


cw_inline void clear_handshake_buf(struct handshake_buffer *buf)
{
    buf->start = buf->avail = buf->buf;
    buf->used = 0;
    buf->left = buf->total = MAX_HANDSHAKE_BUFSIZE;
    memset(buf->start, 0, buf->total);
}


void create_install_client_ctx(int clientfd, int remotefd)
{
    struct client_ctx *client;

    printf("cli fd %d <=>rmt fd %d\n", clientfd, remotefd);
    client = cw_malloc(sizeof(struct client_ctx));
    client->next = NULL;

    client->client_fd = clientfd;
    client->remote_fd = remotefd;
    client->flag = 0;

    client->to.start = client->to.avail = client->to.buf;
    client->to.used = 0;
    client->to.left = client->to.total = MAX_WIRE_BUFSIZE;

    client->fr.start = client->fr.avail = client->fr.buf;
    client->fr.used = 0;
    client->fr.left = client->fr.total = MAX_WIRE_BUFSIZE;

    client->hs_in = cw_malloc(sizeof(struct handshake_buffer));
    client->hs_out = cw_malloc(sizeof(struct handshake_buffer));
    clear_handshake_buf(client->hs_in);
    clear_handshake_buf(client->hs_out);

    setnonblocking(clientfd);
    setnonblocking(remotefd);

    epoll_ctl_wrap(clientfd, EPOLL_CTL_ADD, EPOLLIN);

    install_ctx(cli_rmt_fds, CLIENT_CTX_SIZE, client);
}


static inline void memcpy_lower(void *dst, void *src, size_t len)
{
    char *d = (char *) dst;
    char *s = (char *) src;
    int i;

    for (i = 0; i < len; i++, d++, s++) {
        if (*s >= 'A' && *s <= 'Z')
            *d = *s + 'a' - 'A';
        else
            *d = *s;
    }
}


void create_install_dns_ctx(int dnsfd, int rfd, int cfd, in_port_t port,
            char *hostname)
{
    struct client_ctx *client;

    client = cw_malloc(sizeof(struct client_ctx));
    client->next = NULL;

    client->client_fd = dnsfd;
    client->remote_fd = rfd;
    client->alt_fd = cfd;   // save client fd here
    client->sin_port = port;
    client->fqdn = strdup(hostname);

    install_ctx(dns_rmt_fds, DNS_CTX_SIZE, client);
}


/* read client hello, prepare reply, but do not send yet, wait for the client
 * fd is available for write */
void socks_hs_hello_1(struct client_ctx *cli)
{
    struct handshake_buffer *in, *out;
    Byte *buf;
    uint8_t nmethods, m, method;
    ssize_t nread;

    in = cli->hs_in;
    buf = in->buf;
    //printf("\ndebug handshake: read from fd %d\n", sfd);
    nread = read(cli->client_fd, in->avail, in->left);
    if (nread == -1) {
        if (errno != EWOULDBLOCK) {
            close(cli->remote_fd);
            close(cli->client_fd);
            uninstall_cli_ctx(cli);
        }
        return;
    } else if (nread > 0) {
        in->used += nread;
        in->left -= nread;
        in->avail += nread;
    }

    if (in->used < 3)   // we don't have full hello msg
        return;

    nmethods = buf[1];
    if (in->used < (2 + nmethods)) // we don't have full hello msg
        return;

    method = METHOD_NOACPT;
    // looking for methods client support
    for (m = 0; m < nmethods; m++) {
        if (buf[2 + m] == METHOD_NOAUTH) {
            method = METHOD_NOAUTH;   // only support NO AUTHENTICATION now
            break;
        }
    }

    if (buf[0] != VER_SOCKS5)
        method = METHOD_NOACPT;

    /*******************  prepare server reply  ***********/
    out = cli->hs_out;
    buf = out->buf;
    buf[0] = VER_SOCKS5;   // SOCKS ver 5
    buf[1] = method;
    out->used = 2;
    out->left -= 2;

    clear_handshake_buf(cli->hs_in);  // done with client hello msg

    cli->flag = REPLY_HELLO_1;
    epoll_ctl_wrap(cli->client_fd, EPOLL_CTL_MOD, EPOLLOUT);

    return;
}


/* wake by epoll client fd is good to write, send reply to client's first
 * hello msg
 */
void socks_hs_hello_1_reply(struct client_ctx *cli)
{
    struct handshake_buffer *out;
    Byte *buf;
    ssize_t nwritten;

    out = cli->hs_out;
    buf= out->buf;
    nwritten = write(cli->client_fd, out->start, out->used);
    if (nwritten == -1) {
        if (errno != EWOULDBLOCK) {
            close(cli->remote_fd);
            close(cli->client_fd);
            uninstall_cli_ctx(cli);
        }
        return;
    } else if (nwritten > 0) {
        out->used -= nwritten;
        out->start += nwritten;
    }

    if (out->used > 0)
        return;

    if (buf[1] == METHOD_NOACPT) {
        close(cli->remote_fd);
        close(cli->client_fd);
        uninstall_cli_ctx(cli);
    } else {
        cli->flag = READ_HELLO_2;
        epoll_ctl_wrap(cli->client_fd, EPOLL_CTL_MOD, EPOLLIN);
    }

    return;
}


/* wake up by epoll, read client hello msg 2
 *
 * the remote domain name is resolved by built-in resolve, also non-blocking.
 * if the dns is in the cache, it will try to make non-blocking connect to
 * remote, otherwise just wait be wake up by epoll to parse dns */
void socks_hs_hello_2(struct client_ctx *cli)
{
    struct handshake_buffer *in, *out;
    Byte *buf;
    ssize_t nread;
    int cli_conn_err;

    in = cli->hs_in;
    buf = in->buf;
    //printf("\ndebug handshake: read from fd %d\n", sfd);
    nread = read(cli->client_fd, in->avail, in->left);
    if (nread == -1) {
        if (errno != EWOULDBLOCK) {
            close(cli->remote_fd);
            close(cli->client_fd);
            uninstall_cli_ctx(cli);
        }
        return;
    } else if (nread > 0) {
        in->used += nread;
        in->left -= nread;
        in->avail += nread;
    }

    if (in->used < 5)   // we don't have full hello 2 msg
        return;

    int msglen, n;
    switch (buf[3]) {
    case ATYP_IPV4:
        msglen = 10;
        break;
    case ATYP_IPV6:
        msglen = 22;
        break;
    case ATYP_DOMAIN:
        n = (int)buf[4];
        msglen = 4 + 1 + n + 2;
        break;
    }

    if (in->used < msglen) // we don't have full hello 2 msg
        return;

    cli_conn_err = REP_OKAY;
    if (buf[0] != VER_SOCKS5) // double check socks version
        cli_conn_err = REP_FAIL;

    if (buf[1] != CMD_CONN)
        cli_conn_err = REP_CMDNOTSUPP;

    if (buf[3] == ATYP_IPV6)   // double check socks version
        cli_conn_err = REP_ADDRNOTSUPP;

    /*prepare server reply, socks_hs_hello_2_reply will send the msg */
    out = cli->hs_out;
    buf = out->buf;
    buf[0] = VER_SOCKS5;   // SOCKS ver 5
    buf[1] = cli_conn_err;
    buf[2] = 0x00;  // reserved
    buf[3] = ATYP_IPV4;
    memcpy(&buf[4], &(SERV_BIND_ADDR.sin_addr), 4);
    memcpy(&buf[8], &(SERV_BIND_ADDR.sin_port), 2);

    out->used = 10;
    out->left -= 10;

    cli->flag = REMOTE_NOT_READY;
    // but wait for establish connection to remote
    epoll_ctl_wrap(cli->client_fd, EPOLL_CTL_DEL, 0);

    // connect to remote first
    int dnsfd;
    struct addrinfo *rmtaddr = NULL;
    dnsfd = socks_hs_hello_2_getrmtaddr(cli, &rmtaddr);

    if (dnsfd == 0) {
        socks_hs_hello_2_nonbconnrmt(cli->remote_fd, rmtaddr);
        //epoll_ctl_wrap(cli->remote_fd, EPOLL_CTL_ADD, EPOLLIN | EPOLLOUT);
    }

    cw_freeaddrinfo(rmtaddr);
    return;
}

/*
 * extract dst ip or domain name from client hello message,
 * if ip: fill in the res
 * if domain: try lookup in dns cache, fill in the res if cache hit, other wise
 *            send query to DNS server, add dns udp socket to epoll monitor
 */
int socks_hs_hello_2_getrmtaddr(struct client_ctx *cli, struct addrinfo **res)
{
    Byte *buf;
    struct handshake_buffer *in;
    uint8_t fqdn_len;
    uint16_t port;
    char s_port[8];
    char fqdn[MAX_DOMAINNAME];
    struct addrinfo *rp;
    int dnsfd;
    struct sockaddr_in *tmp;

    in = cli->hs_in;
    buf = in->buf;

    *res = NULL;
    if (buf[3] == ATYP_IPV4) {
        //printf("debug handshake: client hello detail, use ip addr\n");
        rp = cw_malloc(sizeof(struct addrinfo));
        tmp = cw_malloc(sizeof(struct sockaddr_in));
        if (rp == NULL || tmp == NULL) {
            printf("fail to allocate memory");
            return -1;
        }

        tmp->sin_family = AF_INET;
        memcpy(&(tmp->sin_addr), &buf[4], 4);
        memcpy(&(tmp->sin_port), &buf[8], 2);
        rp->ai_addr = (struct sockaddr *) tmp;
        rp->ai_family = AF_INET;
        rp->ai_addrlen = (socklen_t) sizeof(struct sockaddr);
        rp->ai_protocol = 0;
        rp->ai_next = NULL;
        *res = rp;
        return 0;
    }

    if (buf[3] == ATYP_DOMAIN) {
        //printf("debug handshake: client hello detail, use domain\n");
        fqdn_len = buf[4];
        memcpy_lower(&fqdn, &buf[5], (size_t)fqdn_len);
        fqdn[fqdn_len] = '\0';
        memcpy(&port, &buf[5 + fqdn_len], 2);
        sprintf(s_port, "%d", ntohs(port));

        printf("debug handshake: connecting to %s:%s\n", fqdn, s_port);
        //TODO make dns nonblock
        dnsfd = cw_getaddrinfo(fqdn, s_port, &rp);
        if (dnsfd < 0) {
            fprintf(stderr, "fail to looking up %s\n", fqdn);
            return -1;
        } else if (dnsfd == 0) {  // cache hit, rp is the result
            *res = rp;
        } else {                  // dnsfd > 0, rp should be NULL
            //printf("install dnsctx for dfd rfd cfd %d %d %d\n",
            //       dnsfd, rfd,  cfd);
            create_install_dns_ctx(dnsfd, cli->remote_fd, cli->client_fd,
                                   port, fqdn);
            epoll_ctl_wrap(dnsfd, EPOLL_CTL_ADD, EPOLLIN);
        }
    }

    return dnsfd;
}


/* wake up by epoll, try read dns udp reply and parse record, then make
 * non-blocking connect to remote host
 */
void socks_hs_hello_2_wakeupdns(struct client_ctx *dnsctx)
{
    int err;
    struct client_ctx *clictx;
    struct addrinfo *rmtaddr;

    err = read_dns_udp_reply(dnsctx, &rmtaddr);
    if (err == DNSWOULDBLOCK)
        return;

    clictx = lookup_cli_ctx(dnsctx->remote_fd);
    // dns resolve finish, (fail or okay), close udp socket
    close(dnsctx->client_fd);
    uninstall_dns_ctx(dnsctx);
    if (err == -1) {
        close(clictx->remote_fd);
        close(clictx->client_fd);
        uninstall_cli_ctx(clictx);
        return;
    }

    socks_hs_hello_2_nonbconnrmt(clictx->remote_fd, rmtaddr);
    cw_freeaddrinfo(rmtaddr);

    //epoll_ctl_wrap(clictx->remote_fd, EPOLL_CTL_ADD, EPOLLIN | EPOLLOUT);
    return;
}

/* we have addrinfo of remote, now use nonblocking connect.
 * epoll will monitor the remote connect socket fd
 *
 * Arg:
 *      cfd  if 0, means should get client fd from dnsctx
 */
int socks_hs_hello_2_nonbconnrmt(int rfd, struct addrinfo *result)
{
    struct addrinfo *rp;
    struct client_ctx *cli;
    int err = 0;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char *s;
        struct sockaddr_in *tmp;
        tmp = (struct sockaddr_in *) rp->ai_addr;
        s = inet_ntoa(tmp->sin_addr);
        printf("debug handshake: connecting to %s:%d fd %d\n", s,
                ntohs(tmp->sin_port), rfd);

        if (connect(rfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            if (errno == EINPROGRESS) {
                err = 0;
                break;
            } else {
                err = -1;
            }
        }
    }

    if (rp == NULL) {
        fprintf(stderr, "client handshake error: Could not connect\n");
        err = -1;
    }

    cli = lookup_cli_ctx(rfd);

    if (err == -1) {
        close(cli->remote_fd);
        close(cli->client_fd);
        uninstall_cli_ctx(cli);
    } else {
        epoll_ctl_wrap(rfd, EPOLL_CTL_ADD, EPOLLIN | EPOLLOUT);
    }

    //printf("debug handshake: %d client<->remote %d\n", cfd, rfd);
    return err;
}


int socks_hs_hello_2_rmtconn_verify(struct client_ctx *cli)
{
    int error;
    socklen_t len;

    len = sizeof(error);
    if (getsockopt(cli->remote_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        close(cli->remote_fd);
        close(cli->client_fd);
        uninstall_cli_ctx(cli);
        printf("remote fd %d connect verify error\n", cli->remote_fd);
        return -1;
    } else {
        cli->flag = REPLY_HELLO_2;
        epoll_ctl_wrap(cli->client_fd, EPOLL_CTL_ADD, EPOLLOUT);
        //epoll_ctl_wrap(cli->remote_fd, EPOLL_CTL_DEL, 0);
        epoll_ctl_wrap(cli->remote_fd, EPOLL_CTL_MOD, EPOLLIN);
    }

    return 0;
}


/* finally, the connection to remote host established, tell the client
 * handshake done
 */
int socks_hs_hello_2_reply(struct client_ctx *cli)
{
    struct handshake_buffer *out;
    ssize_t nwritten;
    Byte *buf;

    out = cli->hs_out;
    buf = out->buf;
    // server complete  msg already in buffer
    nwritten = write(cli->client_fd, buf, out->used);
    if (nwritten == -1) {
        close(cli->client_fd);
        close(cli->remote_fd);
        uninstall_cli_ctx(cli);
        return -1;
    }

    out->start += nwritten;
    out->used -= nwritten;

    if (out->used == 0) {
        epoll_ctl_wrap(cli->client_fd, EPOLL_CTL_MOD, EPOLLIN);
        cli->flag = HELLO_DONE;
        free(cli->hs_in);
        free(cli->hs_out);
        cli->hs_in = NULL;
        cli->hs_out = NULL;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    struct epoll_event ev, *evns;
    int listen_sock, conn_sock, nfds;
    int rfd;
    int n;
    struct sockaddr in_addr;
    socklen_t in_len;
    //char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    int maxevents = INIT_MAX_EVENTS;
    evns = cw_malloc(maxevents * sizeof(struct epoll_event));

    init_client_ctx();
    init_dns();  // dns cache

    if ((listen_sock = create_and_bind(&SERV_BIND_ADDR, "1080")) == -1)
        exit(EXIT_FAILURE);

    if (listen(listen_sock, SOMAXCONN) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    char *s;
    s = inet_ntoa(SERV_BIND_ADDR.sin_addr);
    printf("listen on %s:%d\n", s, ntohs(SERV_BIND_ADDR.sin_port));

    if ((epfd = epoll_create(1)) == -1) {
        perror("epoll_create");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    while (1) {
        nfds = epoll_wait(epfd, evns, maxevents, -1);
        if (nfds == -1) {
            if (errno == EINTR)  {
                continue;
            } else {
                perror("epoll_wait");
                exit(EXIT_FAILURE);
            }
        }

        if (nfds == maxevents) {
            maxevents *= 2;
            evns = cw_realloc(evns, maxevents * sizeof(struct epoll_event));
            printf("resized maxevents to %d\n", maxevents);
        }

        for (n = 0; n < nfds; ++n) {
            if (evns[n].data.fd == listen_sock) {
                in_len = sizeof(in_addr);
                conn_sock = accept(listen_sock, &in_addr, &in_len);
                if (conn_sock == -1 && errno == EWOULDBLOCK)
                    break;
                /*
                perror("accept");
                if (getnameinfo(&in_addr, in_len,
                                hbuf, sizeof(hbuf),
                                sbuf, sizeof(sbuf),
                                NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                    printf("Accepted connection on fd %d (host=%s, "
                            "port=%s)\n", conn_sock, hbuf, sbuf);
                            */
                rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (rfd == -1) {
                    fprintf(stderr, "client handshake error: socket fail\n");
                    close(conn_sock);
                    continue;
                }

                /* monitor client fd for hello */
                create_install_client_ctx(conn_sock, rfd);
            } else if ((evns[n].events & EPOLLERR) ||
                       (evns[n].events & EPOLLHUP)) {
                epoll_errhup(evns[n].data.fd);
            } else if ((evns[n].events & EPOLLIN) ||
                       (evns[n].events & EPOLLOUT)) {
                    socks5_server(&evns[n]);
            }
        }
    }
}


void epoll_errhup(int fd)
{
    struct client_ctx *cli, *dnsctx;

     printf("\nepoll ERR/HUP: fd %d\n", fd);
    cli = lookup_cli_ctx(fd);
    dnsctx = lookup_dns_ctx(fd);

    if (cli != NULL) {
        close(cli->remote_fd);
        close(cli->client_fd);
        uninstall_cli_ctx(cli);
    } else if (dnsctx != NULL) {
        close(cli->remote_fd);
        close(cli->client_fd);
        uninstall_dns_ctx(dnsctx);
    } else {
        close(fd);
    }
}


/* read the socket into buffer */
void read_wire(int sfd, struct epoll_event *ev, struct client_ctx *cli)
{
    struct wire_buffer *wb;
    struct epoll_event evctx;
    int opp_fd;   // counter-fd
    ssize_t nread;

    if (sfd == cli->remote_fd) {
        wb = &(cli->fr);
        opp_fd = cli->client_fd;
    } else {
        wb = &(cli->to);
        opp_fd = cli->remote_fd;
    }

    if (wb->left > 0) {
        if ((nread = read(sfd, wb->avail, wb->left)) < 0) {
            if (errno != EWOULDBLOCK) {
                fprintf(stderr, "read error from remote\n");
            }
        } else if (nread > 0) {
            wb->avail += nread;
            wb->left -= nread;
            wb->used += nread;
        } else if (nread == 0 && cli->to.used == 0 && cli->fr.used == 0) {
            close(cli->remote_fd);
            close(cli->client_fd);
            uninstall_cli_ctx(cli);

            return;
        }
    }

    if (wb->used > 0) {
        evctx.data.fd = opp_fd;
        evctx.events = EPOLLIN | EPOLLOUT;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, opp_fd, &evctx) == -1) {
            perror("epoll_ctl");
            exit(EXIT_FAILURE);
        }
    }
}

void write_wire(int sfd, struct epoll_event *ev, struct client_ctx *cli)
{
    struct wire_buffer *wb;
    //int fd, opp_fd;   // counter-fd
    ssize_t nwritten;

    if (sfd == cli->remote_fd) {
        wb = &(cli->to);
    } else {
        wb = &(cli->fr);
    }

    if (wb->used > 0) {
        if ((nwritten = write(sfd, wb->start, wb->used)) < 0) {
            if (errno != EWOULDBLOCK)
                fprintf(stderr, "error write to fd %d\n", sfd);
        } else {
            wb->used -= nwritten;
            wb->start += nwritten;
        }
    }

    if (wb->used == 0) {
        wb->start = wb->avail = wb->buf;  // buf drained
        wb->left = wb->total;
        // socket send buffer is empty, disable EPOLLOUT
        epoll_ctl_wrap(sfd, EPOLL_CTL_MOD, EPOLLIN);
    }
}


void socks5_server(struct epoll_event *ev)
{
    struct client_ctx *cli;
    int sfd;

    sfd = ev->data.fd;

    if ((cli = lookup_dns_ctx(sfd)) != NULL) {
        socks_hs_hello_2_wakeupdns(cli);
        return;
    }

    cli = lookup_cli_ctx(sfd);

    if (cli == NULL) {
        printf("debug: fd %d detected by epoll is not in hashtable\n", sfd);
        return;
    }

    if (cli->flag != HELLO_DONE) {
        switch (cli->flag) {
        case READ_HELLO_1:
            socks_hs_hello_1(cli);
            break;
        case REPLY_HELLO_1:
            socks_hs_hello_1_reply(cli);
            break;
        case READ_HELLO_2:
            socks_hs_hello_2(cli);
            break;
        case REMOTE_NOT_READY:
            socks_hs_hello_2_rmtconn_verify(cli);
            break;
        case REPLY_HELLO_2:
            socks_hs_hello_2_reply(cli);
            break;
        default:
            return;
        }
    }

    if (ev->events & EPOLLIN) {
        read_wire(sfd, ev, cli);
    } else if (ev->events & EPOLLOUT) {
        write_wire(sfd, ev, cli);
    }
}
