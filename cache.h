/* cache.h
 * DNS cache management
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


void init_dns(void);
struct addrinfo *lookup_dns_cache(char *fqdn, char *service);
void install_dns_cache(char *fqdn, struct addrinfo *addr, uint32_t ttd);
