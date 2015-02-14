/* common.h
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


#ifndef HDRCOM
#define HDRCOM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>


#define cw_inline static __inline__
typedef unsigned char Byte;


int create_and_bind(struct sockaddr_in *addr, char *port);
int setnonblocking(int sfd);

ssize_t readn(int fd, void *usrbuf, size_t n);
ssize_t writen(int fd, void *usrbuf, size_t n);
int udp_connect(const char *host);
int tcp_connect(const char *host, const char *serv);


/* blacksocks.c */
#define LOGFILE "/var/log/blacksocks/blacksocks.log"
#define PIDFILE "/var/run/blacksocks/blacksocks.pid"
#define WORKDIR "/var/run/blacksocks"

#define VER_SOCKS5  0x05
#define METHOD_NOAUTH  0x00
#define METHOD_NOACPT  0xff   // no acceptable methods
#define CMD_CONN    0x01
#define CMD_BIND    0x02
#define CMD_UDP     0X03

#define REP_OKAY         0x00
#define REP_FAIL         0x01
#define REP_NOTALLOW     0x02
#define REP_NETUNREACH   0x03
#define REP_HOSTUNREACH  0x04
#define REP_CONNREFUSED  0x05
#define REP_TTLEXP       0x06
#define REP_CMDNOTSUPP   0x07
#define REP_ADDRNOTSUPP  0x08
#define ATYP_IPV4    0x01
#define ATYP_DOMAIN  0x03
#define ATYP_IPV6    0x04

struct cw_runtime {
    int epfd;
    char SOCKS_PORT[6];
    char DNS_SERVER[15];
    int maxevents;
    int listen_sock;
    struct epoll_event *evns;
    struct client_ctx *expired_ctx;

    struct client_ctx **known_ctx;  /* for track time out ctx */
    int known_ctx_size;
    int garbage_time;
    FILE *logfp;
    char *pidfile;
} *cw_daemon;

extern struct cw_runtime *cw_daemon;

#define MAX_HANDSHAKE_BUFSIZE 1024
struct handshake_buffer {
    Byte buf[MAX_HANDSHAKE_BUFSIZE];
    Byte *start;
    Byte *avail;
    int used;
    int left;
    int total;
};

#define MAX_WIRE_BUFSIZE 32 * 1024
struct wire_buffer {
    Byte buf[MAX_WIRE_BUFSIZE];
    Byte *start;
    Byte *avail;
    int used;
    int left;
    int total;
};

/* flags client_ctx*/
//#define CLIENT_READY  1
//#define REMOTE_READY  2
//#define DNS_FD        4
#define READ_HELLO_1     0
#define REPLY_HELLO_1    1
#define READ_HELLO_2     2
#define REMOTE_NOT_READY 3
#define REPLY_HELLO_2    4
#define HELLO_DONE       5
#define F_DNS            6


struct client_ctx {
    struct client_ctx *parent;
    struct client_ctx *prev_expired;
    struct client_ctx *next_expired;
    struct client_ctx *prev;
    struct client_ctx *next;

    struct client_ctx *child_remote;
    struct client_ctx *child_client;

    int client_fd;
    int remote_fd;
    int fd;

    char *fqdn;
    in_port_t sin_port;
    uint8_t flag;
    struct wire_buffer *to;  // from client to remote
    struct wire_buffer *fr;
    struct handshake_buffer *hs_in;
    struct handshake_buffer *hs_out;

    int ttd;
};

/* common.c */
#define LOG_BUFSIZE 8 * 1024
void log_debug(char *fmt, ...);

/* dns.c */
#define DNSWOULDBLOCK -2

void init_dns(void);
int cw_getaddrinfo(char *hostname, char *service, struct addrinfo **res);
ssize_t read_dns_udp_reply(struct client_ctx *ctx, struct addrinfo **res);
void cw_freeaddrinfo(struct addrinfo *res);

/* cache.c */
#define DNS_CACHE_SIZE 64 * 1024  /* use 16bit FNV-1 */
struct dns_cache_node *dns_cache[DNS_CACHE_SIZE];

struct dns_cache_node {
    struct dns_cache_node *next;
    uint32_t  ttd;
    uint32_t  hash;
    in_port_t sin_port;
    struct in_addr *sin_addrs;
    uint8_t   acount;
    uint8_t   link_count;
    char      *fqdn;
};

struct addrinfo *lookup_dns_cache(char *fqdn, char *service);
void install_dns_cache(char *fqdn, struct addrinfo *addr, uint32_t ttd);

/* option.c */
#define MAXLINE 1000
#define CONFFILE "/etc/blacksocks.conf"
void loadcfg(char *fname);

#endif
