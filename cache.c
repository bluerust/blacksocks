/* cache.c
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include "cache.h"
#include "common.h"
#include "utils.c"

extern struct dns_cache_node *dns_cache[];

void free_dns_cache_node(struct dns_cache_node *np);
void remove_expired_dns_cache(int idx);

void install_dns_cache(char *fqdn, struct addrinfo *addr, uint32_t ttd);

struct dns_cache_node *addr2cache(char *fqdn, struct addrinfo *addr, uint32_t ttd);
struct addrinfo *cache2addr(struct dns_cache_node *dc, char *service);


void free_dns_cache_node(struct dns_cache_node *np)
{
    free(np->fqdn);
    free(np->sin_addrs);
    free(np);
}


struct addrinfo *lookup_dns_cache(char *fqdn, char *service)
{
    struct dns_cache_node *dc;
    struct addrinfo *res;
    uint32_t now;
    uint32_t h;
    int idx;

    now = (uint32_t) time(NULL);
    h = strhash(fqdn);
    /* use xor folding to transform 32bit hash to 16bit, the hash table size is
     * 2^16, therefor the hash value can used as index directly
     */
    idx = (h>>16) ^ (h & MASK_16);
    for (dc = dns_cache[idx]; dc != NULL && dc->hash != h; dc = dc->next) {
        if (strcmp(fqdn, dc->fqdn) == 0)
            break;
    }

    if (dc == NULL)
        return NULL;

    if (dc->ttd < now) {
        remove_expired_dns_cache(idx);
        return NULL;
    }

    res = cache2addr(dc, service);
    return res;
}


/* convert the cached item back to addrinfo */
struct addrinfo *cache2addr(struct dns_cache_node *dc, char *service)
{
    struct addrinfo *res, *rp, *rtmp;
    struct sockaddr_in *tmp;
    int i;

    res = NULL;
    for (i = 0; i < dc->acount; i++) {
        rp = cw_malloc(sizeof(struct addrinfo));
        tmp = cw_malloc(sizeof(struct sockaddr_in));
        tmp->sin_family = AF_INET;
        memcpy(&(tmp->sin_addr), &(dc->sin_addrs[i]), sizeof(struct sockaddr));
        tmp->sin_port = htons(atoi(service));
        rp->ai_addr = (struct sockaddr *) tmp;
        rp->ai_family = AF_INET;
        rp->ai_addrlen = (socklen_t) sizeof(struct sockaddr);
        rp->ai_protocol = 0;
        rp->ai_next = NULL;

        if (res == NULL) {
            res = rp;
        } else {
            for (rtmp = res; rtmp->ai_next != NULL; rtmp = rtmp->ai_next)
                ;

            rtmp->ai_next = rp;
        }
    }

    return res;
}

struct dns_cache_node *addr2cache(char *fqdn, struct addrinfo *addr, uint32_t ttd)
{
    struct dns_cache_node *dc;
    struct addrinfo *np;
    struct sockaddr_in *tmp;
    int i = 0;

    for (np = addr; np != NULL; np = np->ai_next)
        i++;

    dc = cw_malloc(sizeof(struct dns_cache_node));
    dc->next = NULL;
    dc->fqdn = strdup(fqdn);
    dc->hash = 0;
    dc->ttd = ttd;
    dc->acount = i;
    dc->sin_addrs = cw_malloc(dc->acount * sizeof(struct in_addr));

    i = 0;
    for (np = addr; np != NULL; np = np->ai_next) {
        tmp = (struct sockaddr_in *) np->ai_addr;
        memcpy(&(dc->sin_addrs[i++]), &(tmp->sin_addr), sizeof(struct in_addr));
    }

    tmp = (struct sockaddr_in *) addr->ai_addr;
    dc->sin_port = tmp->sin_port;

    return dc;
}

/* remove cached dns items based on their time to die value */
void remove_expired_dns_cache(int idx)
{
    struct dns_cache_node *np, *child;
    uint32_t now;

    now = (uint32_t) time(NULL);
    np = dns_cache[idx];
    if (np == NULL)
        return;

    while (np != NULL) {
        child = np->next;
        if (child != NULL) {
            if (child->ttd < now) {
                np->next = child->next;
                free_dns_cache_node(child);
            }
        }
        np = np->next;
    }

    np = dns_cache[idx];
    if (np->ttd < now) {
        dns_cache[idx] = np->next;
        free_dns_cache_node(np);
    }
}

void install_dns_cache(char *fqdn, struct addrinfo *addr, uint32_t ttd)
{
    struct dns_cache_node *np, *dc;
    int idx;
    uint32_t h;

    h = strhash(fqdn);
    idx = (h>>16) ^ (h & MASK_16);

    /* only place to do house keeping, remove expired cache */
    remove_expired_dns_cache(idx);
    for (dc = dns_cache[idx]; dc != NULL; dc = dc->next) {
        if (dc->hash == h && strcmp(fqdn, dc->fqdn) == 0)
            return;
    }

    dc = addr2cache(fqdn, addr, ttd);
    dc->hash = h;
    if ((np = dns_cache[idx]) == NULL) {
        dns_cache[idx] = dc;
    } else {
        dc->next = np;
        dns_cache[idx] = dc;
    }
}
