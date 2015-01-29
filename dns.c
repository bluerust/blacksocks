/* dns.c
 *
 * Async dns resolver share the event drive with socks5 server
 *
 * Copyright 2015, Chen Wei <weichen302@gmail.com>
 *
 * License GPLv3: GNU GPL version 3
 * This is free software: you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 *
 * Please send bug reports and questions to Chen Wei <weichen302@gmail.com>
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"
#include "cache.h"
#include "socks5.h"
#include "common.h"
#include "utils.c"

//TODO: add error check
#define MAX_QUESTION 1024
#define UDP_BUFSIZE 2048
#define MAX_DNSMSG  2048

extern int epfd;

int format_domain_name(Byte *domain, char *hostname);
ssize_t parse_rr(Byte *buf, size_t bufsize, in_port_t port,
                 struct addrinfo **res, uint32_t *ttd);
ssize_t parse_udp_buf(Byte *buf, size_t bufsize, in_port_t port,
                      struct addrinfo **addr, uint32_t *ttd);
void log_debug(char *msg);


/* the cache is in cache.c */
extern struct dns_cache_node *dns_cache[];

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t nqes;    // number of questions
    uint16_t nans;    // number of answers
    uint16_t naut;    // number of authority RRs
    uint16_t nadi;    // number of additional RRs
};

struct dns_question {
    uint16_t type;   // 0x01 for A
    uint16_t class;  // 0x01 for internet address
};

/* Resource Record */
struct dns_rr {
    uint16_t type;   // 0x01 for A
    uint16_t class;  // 0x01 for internet address
    uint32_t ttl;
    uint16_t rr_len; // resource data length
};

size_t dns_fill_buf(Byte *buf, char *hostname)
{
    Byte *b, *p;
    struct dns_header header;
    struct dns_question question;
    int size;

    memset(&header, 0, sizeof(header));
    memset(&question, 0, sizeof(question));

    header.id = htons(77);
    header.flags = htons(0x100);
    header.nqes  = htons(1);

    b = p = buf;
    memcpy(b, &(header.id), 2);
    b += 2;

    memcpy(b, &(header.flags), 2);
    b += 2;
    memcpy(b, &(header.nqes), 2);
    b += 8;

    size = format_domain_name(b, hostname);

    b += size;
    question.type = htons(0x01);
    question.class = htons(0x01);
    memcpy(b, &(question.type), 2);
    b += 2;
    memcpy(b, &(question.class), 2);
    b += 2;

    return b - p;
}

ssize_t parse_udp_buf(Byte *buf, size_t bufsize, in_port_t port,
                      struct addrinfo **addr, uint32_t *ttd)
{
    Byte *b;
    uint16_t nans;
    struct dns_header header;
    struct dns_question question;
    ssize_t m;
    int n;
    int i = 0;

    memset(&header, 0, sizeof(header));
    b = buf;
    i += 6;
    memcpy(&(header.nans), &(b[i]), 2);
    i += 6;

    nans = ntohs(header.nans);
    if (nans == 0) {
        log_debug("no answer found\n");
        return -1;
    }

    for ( ; b[i] != 0 && i < bufsize; i++ )
        ;

    i++;  // start of query type
    memset(&question, 0, sizeof(question));
    memcpy(&(question.type), &b[i], 2);
    i += 2;
    memcpy(&(question.class), &b[i], 2);
    i += 2;
    question.type = ntohs(question.type);
    question.class = ntohs(question.class);
    if (question.type != 0x01)  // type A
        return -1;

    for (n = 0; n < nans; n++) {
        m = parse_rr(&b[i], bufsize - i, port, addr, ttd);
        if (m == -1)
            return -1;
        i += m;
    }

    return 0;
}

ssize_t parse_rr(Byte *buf, size_t bufsize, in_port_t port,
                 struct addrinfo **res, uint32_t *ttd)
{
    struct in_addr addr;
    struct sockaddr_in *tmp;
    struct addrinfo *rp, *rs;
    uint16_t rdata_len, type;
    Byte *b;
    int i = 0;

    b = buf;
    // skip domain name in resource record
    if (b[0] & 0xc0) {
        i += 2;
    } else {
        for ( ; b[i] != 0 && i < bufsize; i++ )
            ;
        i++;
    }

    memcpy(&type, &(b[i]), 2);
    type = ntohs(type);

    i += 4;
    memcpy(ttd, &(b[i]), 4);
    /* time to die, determin cache expire */
    *ttd = ntohl(*ttd);
    *ttd += (uint32_t) time(NULL);

    i += 4;
    memcpy(&rdata_len, &b[i], 2);
    i += 2;

    rdata_len = ntohs(rdata_len);
    if (type == 1) {
        memcpy(&addr, &b[i], 4);
        rp = cw_malloc(sizeof(struct addrinfo));
        tmp = cw_malloc(sizeof(struct sockaddr_in));
        if (rp == NULL || tmp == NULL) {
            log_debug("parse_rr: fail to allocate memory");
            return -1;
        }

        tmp->sin_family = AF_INET;
        tmp->sin_addr = addr;
        tmp->sin_port = port;
        rp->ai_addr = (struct sockaddr *) tmp;
        rp->ai_family = AF_INET;
        rp->ai_addrlen = (socklen_t) sizeof(struct sockaddr);
        rp->ai_protocol = 0;
        rp->ai_next = NULL;

        if (*res == NULL) {
            *res = rp;
        } else {
            for (rs = *res; rs->ai_next != NULL; rs = rs->ai_next)
                ;

            rs->ai_next = rp;
        }
    }

    i += rdata_len;
    if (i > (bufsize + 1))
        return -1;
    else
        return i;
}


void log_debug(char *msg)
{
    fprintf(stderr, msg);
}

/* store result in res if cache hit, otherwise just send udp request,
 * wait for epoll to wake up read_dns_udp_reply to actually get result
 *
 * If client get NULL result, it should try read_dns_udp_reply later
 * Return:
 *          -1 on error;
 *          0  on cache hit
 *          >0 for dns sockfd
 */
int cw_getaddrinfo(char *hostname, char *service, struct addrinfo **res)
{
    Byte buf[MAX_DNSMSG];
    int dnsfd;
    size_t size;
    ssize_t err;
    struct addrinfo *dc;

    *res = NULL;
    if ((dc = lookup_dns_cache(hostname, service)) != NULL) {
        *res = dc;
        return 0;
    }

    memset(&buf, 0, sizeof(buf));
    size = dns_fill_buf(buf, hostname);
    dnsfd = udp_connect(DNS_SERVER);
    if (dnsfd == -1) {
        log_debug("socket connect fail\n");
        return -1;
    }

    //printf("dns udp fd= %d\n", dnsfd);
    err = send(dnsfd, &buf, size, 0);
    if (err == -1) {
        log_debug("fail to send dns query\n");
        return -1;
    }

    setnonblocking(dnsfd);
    /* the caller shall add dnsfd to epoll monitor */

    return dnsfd;
}


/* port should in network byte order */
ssize_t read_dns_udp_reply(struct client_ctx *ctx, struct addrinfo **res)
{
    Byte inbuf[MAX_DNSMSG];
    ssize_t err;
    uint32_t ttd;
    int dnsfd;

    *res = NULL;
    dnsfd = ctx->client_fd;
    memset(&inbuf, 0, sizeof(inbuf));
    err = recv(dnsfd, &inbuf, sizeof(inbuf), 0);
    if (err == -1) {
        if (errno == EWOULDBLOCK)
            return DNSWOULDBLOCK;
        else
            return -1;
    } else if (err == 0) {  // peer shutdown
        log_debug("dns reply has size 0\n");
        return 0;
    }

    err = parse_udp_buf(inbuf, err, ctx->sin_port, res, &ttd);
    if (err == -1) {
        log_debug("fail to parse dns query result\n");
        return -1;
    }

    printf("install dns for %s\n", ctx->fqdn);
    install_dns_cache(ctx->fqdn, *res, ttd);
    return 0;
}


void cw_freeaddrinfo(struct addrinfo *res)
{
    struct addrinfo *rp, *tmp;

    if (res == NULL)
        return;

    rp = res;
    while (res->ai_next != NULL) {
        for (rp = res ; rp->ai_next != NULL; rp = rp->ai_next )
            tmp = rp;

        // rp is the last item on linked list
        free(rp->ai_addr);
        free(rp);

        rp = tmp;
        rp->ai_next = NULL;
    }

    free(res->ai_addr);
    free(res);
}


/* format www.yahoo.com as 3www5yahoo3com */
int format_domain_name(Byte *domain, char *hostname)
{
    int i, n;
    Byte *b, *p;

    b = p = domain;
    /* count length of domain label */
    n = 0;
    for (i = 0; hostname[i] != '\0'; i++) {
        if (hostname[i] == '.') {
            *p = i - n;
            p = b + i + 1;
            n = i + 1;  // point to first letter of label
        } else {
            b[i + 1] = (Byte)hostname[i];
        }
    }

    // i point to \0
    *p = i - n;
    b[i + 1] = 0x00;

    return i + 2;
}


/* zero out the cache */
void init_dns(void)
{
    int i;

    for (i = 0; i < DNS_CACHE_SIZE; i++)
        dns_cache[i] = NULL;
}
