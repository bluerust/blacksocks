/* socks5.h
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

#ifndef HDRSOCKS5
#define HDRSOCKS5


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

/* extern, plan to share epoll fd with other module */
int epfd;


#define MAX_HANDSHAKE_BUFSIZE 1024
struct handshake_buffer {
    Byte buf[MAX_HANDSHAKE_BUFSIZE];
    Byte *start;
    Byte *avail;
    int used;
    int left;
    int total;
};

#define MAX_WIRE_BUFSIZE 8 * 1024
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


struct client_ctx {
    struct client_ctx *next;
    int client_fd;  // share with socks client and dns query
    int remote_fd;
    int alt_fd;
    char *fqdn;
    in_port_t sin_port;
    uint8_t flag;
    struct wire_buffer to;  // from client to remote
    struct wire_buffer fr;
    struct handshake_buffer *hs_in;
    struct handshake_buffer *hs_out;
};


#endif
