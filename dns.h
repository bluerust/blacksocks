/* dns.h
 * make, send, read, parse dns request
 *
 * Copyright 2015, Chen Wei <weichen302@gmail.com>
 *
 * License GPLv3: GNU GPL version 3
 * This is free software: you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 *
 * Please send bug reports and questions to Chen Wei <weichen302@gmail.com>
 */


#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include "socks5.h"

#define DNS_SERVER "8.8.8.8"
//char DNS_SERVER[15];
#define DNSWOULDBLOCK -2


void init_dns(void);
int cw_getaddrinfo(char *hostname, char *service, struct addrinfo **res);
ssize_t read_dns_udp_reply(struct client_ctx *ctx, struct addrinfo **res);
void cw_freeaddrinfo(struct addrinfo *res);
