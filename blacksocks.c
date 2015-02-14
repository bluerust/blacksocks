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

#include <unistd.h>
#include <sys/stat.h>
#include "utils.c"
#include "common.h"

/* 64 is not small, will increase in run time if necessary */
#define INIT_MAX_EVENTS  64
#define MAX_DOMAINNAME 256
#define CLIENT_CTX_SIZE  64
#define TIMEOUT          120
#define GARBAGE_INTERVAL 300

struct cw_runtime *cw_daemon;

struct sockaddr_in SERV_BIND_ADDR;

// prototypes
static inline void memcpy_lower(void *dst, void *src, size_t len);
static void read_wire(struct epoll_event *ev, struct client_ctx *cli);
static void write_wire(struct epoll_event *ev, struct client_ctx *cli);
static void epoll_errhup(struct epoll_event *ev);

static void socks_hs_hello_1(struct client_ctx *ctx);
static void  socks_hs_hello_1_reply(struct client_ctx *ctx);
static void socks_hs_hello_2(struct client_ctx *ctx);
static int socks_hs_hello_2_getrmtaddr(struct client_ctx *cli,
                                       struct addrinfo **res);
static void socks_hs_hello_2_wakeupdns(struct client_ctx *dnsctx);
static int  socks_hs_hello_2_nonbconnrmt(struct client_ctx *ctx,
                                         struct addrinfo *result);
static int  socks_hs_hello_2_rmtconn_verify(struct client_ctx *cli);
static int  socks_hs_hello_2_reply(struct client_ctx *cli);
static inline void main_loop(void);
static void daemon_init(void);

static void socks5_server(struct epoll_event *ev);

/* -------------------- context --------------------- */
static void install_ctx(struct client_ctx *ctx);
static inline void mark_for_delete(struct client_ctx *ctx);
static inline void delete_expired_ctx(void);

static void create_install_client_ctx(int clientfd, int remotefd);
static void create_install_dns_ctx(int dnsfd, struct client_ctx *cli, in_port_t port,
                            char *hostname);

static inline void uninstall_cli_ctx(struct client_ctx *ctx);
static inline void free_ctx(struct client_ctx *ctx);
static void garbage_ctx(void);
/* -------------------- end context --------------------- */

cw_inline void clear_handshake_buf(struct handshake_buffer *buf);
cw_inline void epoll_ctl_wrap(int op, int fd, int type, void *ptr);

/* epoll_ctl needs too many sentences */
cw_inline void epoll_ctl_wrap(int op, int fd, int type, void *ptr)
{
    struct epoll_event ev;

    ev.events = type;
    ev.data.ptr = ptr;
    if (epoll_ctl(cw_daemon->epfd, op, fd, &ev) == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}


static void install_ctx(struct client_ctx *ctx)
{
    int i;

    i = ctx->remote_fd % cw_daemon->known_ctx_size;

    if (cw_daemon->known_ctx[i] == NULL) {
        cw_daemon->known_ctx[i] = ctx;
    } else {
        ctx->next = cw_daemon->known_ctx[i];
        ctx->next->prev = ctx;
        cw_daemon->known_ctx[i] = ctx;
    }

}

/* add to daemon->expired_ctx linked list, waiting for delete */
static inline void mark_for_delete(struct client_ctx *ctx)
{
    if (ctx->parent != NULL)
        ctx = ctx->parent;

    if (ctx->prev_expired != NULL || ctx->next_expired != NULL)
        return;

    if (cw_daemon->expired_ctx == NULL) {
        cw_daemon->expired_ctx = ctx;
    } else if (cw_daemon->expired_ctx->next_expired == NULL &&
               cw_daemon->expired_ctx->remote_fd == ctx->remote_fd){
        return; // duplicate
    } else {
        ctx->next_expired = cw_daemon->expired_ctx;
        cw_daemon->expired_ctx->prev_expired = ctx;
        cw_daemon->expired_ctx = ctx;
    }

}


/* delete all ctx in daemon->expired_ctx linked list */
static inline void delete_expired_ctx(void)
{
    struct client_ctx *ctx, *next;

    if ((ctx = cw_daemon->expired_ctx) == NULL)
        return;

    while (ctx != NULL) {
        next = ctx->next_expired;
        uninstall_cli_ctx(ctx);
        ctx = next;
    }

    cw_daemon->expired_ctx = NULL;

    return;
}

/* remove ctx from garbage tracking, then free it */
static inline void uninstall_cli_ctx(struct client_ctx *ctx)
{
    struct client_ctx *prev, *next;
    int i;

    i = ctx->remote_fd % cw_daemon->known_ctx_size;

    prev = ctx->prev;
    next = ctx->next;
    if (next != NULL)
        next->prev = prev;

    if (prev != NULL)
        prev->next = next;
    else
        cw_daemon->known_ctx[i] = next;

    free_ctx(ctx);
}

static inline void free_ctx(struct client_ctx *ctx)
{
    struct client_ctx *parent;

    //printf("free_ctx: free ctx with remote_fd = %d\n", ctx->remote_fd);

    if (ctx->parent == NULL)
        parent = ctx;
    else
        parent = ctx->parent;

    /* not dns fd */
    if (parent->client_fd > 0) {
        close(parent->client_fd);
        free(parent->child_client);
        free(parent->child_remote);
    }

    close(parent->remote_fd);

    free(parent->to);
    free(parent->fr);
    free(parent->hs_in);
    free(parent->hs_out);
    free(parent->fqdn);
    free(parent);
}

/* wake up periodically to remove ttd ctx */
static void garbage_ctx(void)
{
    int i, now;
    struct client_ctx *ctx;
    //int count = 0;

    now = (int) time(NULL);
    for (i = 0; i < cw_daemon->known_ctx_size; i++) {
        for (ctx = cw_daemon->known_ctx[i]; ctx != NULL; ctx = ctx->next) {
            if (ctx->ttd < now) {
                /* could delete ctx directly here, but then daemon->expired_ctx
                 * should be checked */
                mark_for_delete(ctx);
                //count++;
            }
        }
    }

    //printf("  garbage done, mark %d ctx for remove\n", count);
    delete_expired_ctx();
    cw_daemon->garbage_time = GARBAGE_INTERVAL + (int)time(NULL);
}

static inline struct client_ctx *new_client_ctx(void)
{
    struct client_ctx *ctx;

    ctx = cw_malloc(sizeof(struct client_ctx));
    memset(ctx, 0 , sizeof(struct client_ctx));
    ctx->parent = NULL;
    ctx->prev_expired = NULL;
    ctx->next_expired = NULL;
    ctx->next = NULL;
    ctx->prev = NULL;
    ctx->child_remote = NULL;
    ctx->child_client = NULL;
    ctx->fqdn = NULL;
    ctx->hs_in = NULL;
    ctx->hs_out = NULL;
    ctx->to = NULL;
    ctx->fr = NULL;
    ctx->flag = 0;
    ctx->ttd = TIMEOUT + (int)time(NULL);
    return ctx;
}


static void create_install_client_ctx(int clientfd, int remotefd)
{
    struct client_ctx *ctx, *child;

    //printf("cli fd %d <=>rmt fd %d\n", clientfd, remotefd);

    ctx = new_client_ctx();

    ctx->client_fd = clientfd;
    ctx->remote_fd = remotefd;
    ctx->flag = 0;

    ctx->to = cw_malloc(sizeof(struct wire_buffer));
    memset(ctx->to, 0, sizeof(struct wire_buffer));
    ctx->to->start = ctx->to->avail = ctx->to->buf;
    ctx->to->used = 0;
    ctx->to->left = ctx->to->total = MAX_WIRE_BUFSIZE;

    ctx->fr = cw_malloc(sizeof(struct wire_buffer));
    memset(ctx->fr, 0, sizeof(struct wire_buffer));
    ctx->fr->start = ctx->fr->avail = ctx->fr->buf;
    ctx->fr->used = 0;
    ctx->fr->left = ctx->fr->total = MAX_WIRE_BUFSIZE;

    ctx->hs_in = cw_malloc(sizeof(struct handshake_buffer));
    ctx->hs_out = cw_malloc(sizeof(struct handshake_buffer));
    clear_handshake_buf(ctx->hs_in);
    clear_handshake_buf(ctx->hs_out);

    setnonblocking(clientfd);
    setnonblocking(remotefd);

    epoll_ctl_wrap(EPOLL_CTL_ADD, clientfd, EPOLLIN, ctx);

    /* init two children to separate fd for read_wire & write_wire */
    child = new_client_ctx();
    child->parent = ctx;
    child->client_fd = clientfd;
    child->remote_fd = remotefd;
    child->fd = remotefd;
    ctx->child_remote = child;

    child = new_client_ctx();
    child->parent = ctx;
    child->client_fd = clientfd;
    child->remote_fd = remotefd;
    child->fd = clientfd;
    ctx->child_client = child;

    install_ctx(ctx);
}


static void create_install_dns_ctx(int dnsfd, struct client_ctx *cli, in_port_t port,
                            char *hostname)
{
    struct client_ctx *dnsctx;

    dnsctx = new_client_ctx();

    dnsctx->client_fd = 0;
    dnsctx->remote_fd = dnsfd;
    dnsctx->flag = F_DNS;
    dnsctx->child_client = cli;

    dnsctx->sin_port = port;
    dnsctx->fqdn = strdup(hostname);

    install_ctx(dnsctx);
    epoll_ctl_wrap(EPOLL_CTL_ADD, dnsfd, EPOLLIN, dnsctx);
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


cw_inline void clear_handshake_buf(struct handshake_buffer *buf)
{
    buf->start = buf->avail = buf->buf;
    buf->used = 0;
    buf->left = buf->total = MAX_HANDSHAKE_BUFSIZE;
    memset(buf->start, 0, buf->total);
}


/* read client hello, prepare reply, but do not send yet, wait for the client
 * fd is available for write */
static void socks_hs_hello_1(struct client_ctx *cli)
{
    struct handshake_buffer *in, *out;
    Byte *buf;
    uint8_t nmethods, m, method;
    ssize_t nread;

    in = cli->hs_in;
    buf = in->buf;
    //printf("\ndebug handshake: read from fd %d\n", cli->client_fd);
    nread = read(cli->client_fd, in->avail, in->left);
    if (nread == -1) {
        if (errno != EWOULDBLOCK) {
            mark_for_delete(cli);
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
    epoll_ctl_wrap(EPOLL_CTL_MOD, cli->client_fd, EPOLLOUT, cli);

    return;
}


/* wake by epoll client fd is good to write, send reply to client's first
 * hello msg
 */
static void socks_hs_hello_1_reply(struct client_ctx *cli)
{
    struct handshake_buffer *out;
    Byte *buf;
    ssize_t nwritten;

    out = cli->hs_out;
    buf= out->buf;
    nwritten = write(cli->client_fd, out->start, out->used);
    if (nwritten == -1) {
        if (errno != EWOULDBLOCK) {
            mark_for_delete(cli);
        }
        return;
    } else if (nwritten > 0) {
        out->used -= nwritten;
        out->start += nwritten;
    }

    if (out->used > 0)
        return;

    if (buf[1] == METHOD_NOACPT) {
        mark_for_delete(cli);
    } else {
        cli->flag = READ_HELLO_2;
        epoll_ctl_wrap(EPOLL_CTL_MOD, cli->client_fd, EPOLLIN, cli);
    }

    return;
}


/* wake up by epoll, read client hello msg 2
 *
 * the remote domain name is resolved by built-in resolve, also non-blocking.
 * if the dns is in the cache, it will try to make non-blocking connect to
 * remote, otherwise just wait be wake up by epoll to parse dns */
static void socks_hs_hello_2(struct client_ctx *cli)
{
    struct handshake_buffer *in, *out;
    Byte *buf;
    ssize_t nread;
    int cli_conn_err;
    int msglen, n;

    in = cli->hs_in;
    buf = in->buf;
    //printf("\ndebug handshake: read from fd %d\n", sfd);
    nread = read(cli->client_fd, in->avail, in->left);
    if (nread == -1) {
        if (errno != EWOULDBLOCK) {
            mark_for_delete(cli);
        }
        return;
    } else if (nread > 0) {
        in->used += nread;
        in->left -= nread;
        in->avail += nread;
    }

    if (in->used < 5)   // we don't have full hello 2 msg
        return;

    msglen = 0;
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

    // but wait for establish connection to remote
    epoll_ctl_wrap(EPOLL_CTL_DEL, cli->client_fd, 0, cli);

    // connect to remote first
    int dnsfd;
    struct addrinfo *rmtaddr = NULL;
    dnsfd = socks_hs_hello_2_getrmtaddr(cli, &rmtaddr);

    if (dnsfd == 0) {
        socks_hs_hello_2_nonbconnrmt(cli, rmtaddr);
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
static int socks_hs_hello_2_getrmtaddr(struct client_ctx *cli, struct addrinfo **res)
{
    Byte *buf;
    struct handshake_buffer *in;
    uint8_t fqdn_len;
    uint16_t port;
    char s_port[8];
    char fqdn[MAX_DOMAINNAME];
    struct addrinfo *rp;
    struct sockaddr_in *tmp;
    int dnsfd = -1;

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

        //printf("debug handshake: connecting to %s:%s\n", fqdn, s_port);
        //TODO make dns nonblock
        dnsfd = cw_getaddrinfo(fqdn, s_port, &rp);
        if (dnsfd < 0) {
            log_debug("fail to looking up %s\n", fqdn);
            return -1;
        } else if (dnsfd == 0) {  // cache hit, rp is the result
            *res = rp;
        } else {                  // dnsfd > 0, rp should be NULL
            create_install_dns_ctx(dnsfd, cli, port, fqdn);
        }
    }

    return dnsfd;
}


/* wake up by epoll, try read dns udp reply and parse record, then make
 * non-blocking connect to remote host
 */
static void socks_hs_hello_2_wakeupdns(struct client_ctx *dnsctx)
{
    int err;
    struct client_ctx *clictx;
    struct addrinfo *rmtaddr;

    err = read_dns_udp_reply(dnsctx, &rmtaddr);
    if (err == DNSWOULDBLOCK)
        return;

    //clictx = lookup_cli_ctx(dnsctx->remote_fd);
    clictx = dnsctx->child_client;
    // dns resolve finish, (fail or okay), close udp socket
    mark_for_delete(dnsctx);
    if (err == -1) {
        mark_for_delete(clictx);
        return;
    }

    socks_hs_hello_2_nonbconnrmt(clictx, rmtaddr);
    cw_freeaddrinfo(rmtaddr);

    return;
}

/* we have addrinfo of remote, now use nonblocking connect.
 * epoll will monitor the remote connect socket fd
 *
 * Arg:
 *      cfd  if 0, means should get client fd from dnsctx
 */
static int socks_hs_hello_2_nonbconnrmt(struct client_ctx *cli, struct addrinfo *result)
{
    struct addrinfo *rp;
    int err = 0;
    int rfd;

    rfd = cli->remote_fd;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
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
        log_debug("client handshake error: Could not connect\n");
        err = -1;
    }

    if (err == -1) {
        mark_for_delete(cli);
    } else {
        cli->flag = REMOTE_NOT_READY;
        epoll_ctl_wrap(EPOLL_CTL_ADD, rfd, EPOLLIN | EPOLLOUT, cli);
    }

    return err;
}


static int socks_hs_hello_2_rmtconn_verify(struct client_ctx *cli)
{
    int error;
    socklen_t len;

    len = sizeof(error);
    if (getsockopt(cli->remote_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        mark_for_delete(cli);
        printf("remote fd %d connect verify error\n", cli->remote_fd);
        return -1;
    } else {
        //printf("debug handshake: connected via fd %d\n", cli->remote_fd);
        cli->flag = REPLY_HELLO_2;
        epoll_ctl_wrap(EPOLL_CTL_ADD, cli->client_fd, EPOLLOUT, cli);
        epoll_ctl_wrap(EPOLL_CTL_DEL, cli->remote_fd, 0, cli);
    }

    return 0;
}


/* finally, the connection to remote host established, tell the client
 * handshake done
 */
static int socks_hs_hello_2_reply(struct client_ctx *cli)
{
    struct handshake_buffer *out;
    ssize_t nwritten;
    Byte *buf;

    out = cli->hs_out;
    buf = out->buf;
    // server complete  msg already in buffer
    nwritten = write(cli->client_fd, buf, out->used);
    if (nwritten == -1) {
        mark_for_delete(cli);
        return -1;
    }

    out->start += nwritten;
    out->used -= nwritten;

    if (out->used == 0) {
        free(cli->hs_in);
        free(cli->hs_out);
        cli->hs_in = NULL;
        cli->hs_out = NULL;
        cli->flag = HELLO_DONE;

        cli->child_client->flag = HELLO_DONE;
        cli->child_remote->flag = HELLO_DONE;

        epoll_ctl_wrap(EPOLL_CTL_DEL, cli->client_fd, 0, NULL);
        epoll_ctl_wrap(EPOLL_CTL_ADD, cli->client_fd, EPOLLIN,
                       cli->child_client);
        epoll_ctl_wrap(EPOLL_CTL_ADD, cli->remote_fd, EPOLLIN,
                       cli->child_remote);

    }

    return 0;
}


static void daemon_init(void)
{
    int i;

    cw_daemon = malloc(sizeof(struct cw_runtime));
    memset(cw_daemon, 0, sizeof(struct cw_runtime));

    loadcfg(CONFFILE);
    cw_daemon->maxevents = INIT_MAX_EVENTS;
    cw_daemon->evns = cw_malloc(cw_daemon->maxevents *
                                sizeof(struct epoll_event));
    cw_daemon->known_ctx_size = CLIENT_CTX_SIZE;
    cw_daemon->known_ctx = cw_malloc(cw_daemon->known_ctx_size *
                                     sizeof(void *));
    for (i = 0; i < CLIENT_CTX_SIZE; i++)
        cw_daemon->known_ctx[i] = NULL;

    cw_daemon->expired_ctx = NULL;
    cw_daemon->garbage_time = GARBAGE_INTERVAL + (int)time(NULL);

    if ((cw_daemon->listen_sock = create_and_bind(&SERV_BIND_ADDR,
                                       cw_daemon->SOCKS_PORT)) == -1)
        exit(EXIT_FAILURE);

    if (listen(cw_daemon->listen_sock, SOMAXCONN) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    cw_daemon->logfp = fopen(LOGFILE, "a");
    cw_daemon->pidfile = PIDFILE;

    char *s;
    s = inet_ntoa(SERV_BIND_ADDR.sin_addr);
    log_debug("listen on %s:%d\n", s, ntohs(SERV_BIND_ADDR.sin_port));

    if ((cw_daemon->epfd = epoll_create(1)) == -1) {
        perror("epoll_create");
        exit(EXIT_FAILURE);
    }

    struct client_ctx *listen_ctx;

    /* valgrind will report leak on this ctx since it is not tracked */
    listen_ctx = new_client_ctx();
    listen_ctx->fd = cw_daemon->listen_sock;

    epoll_ctl_wrap(EPOLL_CTL_ADD, listen_ctx->fd, EPOLLIN, listen_ctx);

    init_dns();  // dns cache

}


int main(int argc, char *argv[])
{
    FILE *fp;
    pid_t pid, sid;

    daemon_init();

    if (argc == 1) {
        if ((pid = fork()) < 0) {
            log_debug("fork() error\n");
            exit(EXIT_FAILURE);
        }

        /* exit parent */
        if (pid > 0)
            exit(EXIT_SUCCESS);

        umask(0);

        if ((sid = setsid()) < 0) {
            log_debug("setsid() error\n");
            exit(EXIT_FAILURE);
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        int fd;
        fd = open("/dev/null", O_RDONLY);
        if (fd == -1)
            log_debug("Failed to open /dev/null\n");
        else if (fd != 0) {
            if (dup2(fd, 0) == -1)
                log_debug("Failed to reserve fd 0\n");
            close(fd);
        }

        fd = open("/dev/null", O_WRONLY);
        if (fd == -1)
            log_debug("Failed to open /dev/null\n");
        else if (fd != 1) {
            if (dup2(fd, 1) == -1)
                log_debug("Failed to reserve fd 1\n");
            close(fd);
        }

        fd = open("/dev/null", O_WRONLY);
        if (fd == -1)
            log_debug("Failed to open /dev/null\n");
        else if (fd != 2) {
            if (dup2(fd, 2) == -1)
                log_debug("Failed to reserve fd 2\n");
            close(fd);
        }

        if ((chdir(WORKDIR) < 0)) {
            log_debug("chdir error\n");
            exit(EXIT_FAILURE);
        }

        pid = getpid();
        if (cw_daemon->pidfile != NULL &&
                (fp = fopen(cw_daemon->pidfile, "w")) != NULL) {
            fprintf(fp, "%u\n", (unsigned) pid);
            fclose(fp);
        } else {
            log_debug("Can not create pidfile %s\n", cw_daemon->pidfile);
            exit(EXIT_FAILURE);
        }

    }

    while (1) {
        main_loop();
        delete_expired_ctx();
        if (cw_daemon->garbage_time < (int)time(NULL))
            garbage_ctx();
    }

    return 0;
}


static inline void main_loop(void)
{
    int conn_sock, nfds;
    int rfd;
    int n;
    struct sockaddr in_addr;
    socklen_t in_len;

    nfds = epoll_wait(cw_daemon->epfd, cw_daemon->evns, cw_daemon->maxevents, -1);
    if (nfds == -1) {
        if (errno == EINTR)  {
            return;
        } else {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }
    }

    if (nfds == cw_daemon->maxevents) {
        cw_daemon->maxevents *= 2;
        cw_daemon->evns = cw_realloc(cw_daemon->evns, cw_daemon->maxevents * sizeof(struct epoll_event));
        printf("resized cw_daemon->maxevents to %d\n", cw_daemon->maxevents);
    }

    struct client_ctx *ctx;

    for (n = 0; n < nfds; ++n) {
        ctx = (struct client_ctx *) cw_daemon->evns[n].data.ptr;
        if (ctx->fd == cw_daemon->listen_sock) {
            in_len = sizeof(in_addr);
            conn_sock = accept(cw_daemon->listen_sock, &in_addr, &in_len);
            if (conn_sock == -1 && errno == EWOULDBLOCK)
                break;
            /*
            char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
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
                log_debug("client handshake error: socket fail\n");
                close(conn_sock);
                continue;
            }

            /* monitor client fd for hello */
            create_install_client_ctx(conn_sock, rfd);
        } else if ((cw_daemon->evns[n].events & EPOLLERR) ||
                   (cw_daemon->evns[n].events & EPOLLHUP)) {
            epoll_errhup(&cw_daemon->evns[n]);
        } else if ((cw_daemon->evns[n].events & EPOLLIN) ||
                   (cw_daemon->evns[n].events & EPOLLOUT)) {
                socks5_server(&cw_daemon->evns[n]);
        }
    }
}


static void epoll_errhup(struct epoll_event *ev)
{
    struct client_ctx *ctx;

    ctx = (struct client_ctx *) ev->data.ptr;

    mark_for_delete(ctx);
}


/* read the socket into buffer */
static void read_wire(struct epoll_event *ev, struct client_ctx *cli)
{
    struct wire_buffer *wb;
    struct client_ctx *opp_ctx;
    int opp_fd, sfd;
    ssize_t nread;

    if (cli->fd == cli->remote_fd) {
        wb = cli->parent->fr;
        opp_fd = cli->client_fd;
        opp_ctx = cli->parent->child_client;
    } else {
        wb = cli->parent->to;
        opp_fd = cli->remote_fd;
        opp_ctx = cli->parent->child_remote;
    }

    sfd = cli->fd;

    if (wb->left > 0) {
        if ((nread = read(sfd, wb->avail, wb->left)) < 0) {
            if (errno != EWOULDBLOCK) {
                log_debug("read error from remote\n");
            }
        } else if (nread > 0) {
            wb->avail += nread;
            wb->left -= nread;
            wb->used += nread;
        } else if (nread == 0) {
            mark_for_delete(cli->parent);
            return;
        }
    }

    if (wb->used > 0) {
        epoll_ctl_wrap(EPOLL_CTL_MOD, opp_fd, EPOLLIN | EPOLLOUT, opp_ctx);
    }
}

static void write_wire(struct epoll_event *ev, struct client_ctx *cli)
{
    struct wire_buffer *wb;
    int sfd;
    ssize_t nwritten;

    /*
    struct client_ctx *opp_ctx;
    if (cli->fd == cli->remote_fd) {
        opp_ctx = cli->parent->child_client;
    } else {
        opp_ctx = cli->parent->child_remote;
    }
    */

    if (cli->fd == cli->remote_fd) {
        wb = cli->parent->to;
    } else {
        wb = cli->parent->fr;
    }

    sfd = cli->fd;

    if (wb->used > 0) {
        if ((nwritten = write(sfd, wb->start, wb->used)) < 0) {
            if (errno != EWOULDBLOCK)
                log_debug("error write to fd %d\n", sfd);
        } else {
            //printf("write_wire: write %u bytes\n", (unsigned) nwritten);
            wb->used -= nwritten;
            wb->start += nwritten;
        }
    }

    if (wb->used == 0) {
        wb->start = wb->avail = wb->buf;  // buf drained
        wb->left = wb->total;
        // socket send buffer is empty, disable EPOLLOUT
        epoll_ctl_wrap(EPOLL_CTL_MOD, cli->fd, EPOLLIN, cli);
    }
}


static void socks5_server(struct epoll_event *ev)
{
    struct client_ctx *ctx;

    ctx = (struct client_ctx *) ev->data.ptr;

    if (ctx->flag != HELLO_DONE) {
        ctx->ttd = TIMEOUT + (int)time(NULL);
        switch (ctx->flag) {
        case F_DNS:
            socks_hs_hello_2_wakeupdns(ctx);
            break;
        case READ_HELLO_1:
            socks_hs_hello_1(ctx);
            break;
        case REPLY_HELLO_1:
            socks_hs_hello_1_reply(ctx);
            break;
        case READ_HELLO_2:
            socks_hs_hello_2(ctx);
            break;
        case REMOTE_NOT_READY:
            socks_hs_hello_2_rmtconn_verify(ctx);
            break;
        case REPLY_HELLO_2:
            socks_hs_hello_2_reply(ctx);
            break;
        }
        return;
    }

    ctx->parent->ttd = TIMEOUT + (int)time(NULL);
    if (ev->events & EPOLLIN) {
        read_wire(ev, ctx);
    } else if (ev->events & EPOLLOUT) {
        write_wire(ev, ctx);
    }
}
