/* utils.c
 *
 * various routines for hash, memory managment etc.al
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

#define max(A, B) ((A) > (B) ? (A) : (B))

cw_inline void *cw_realloc(void *ptr, size_t size);

#define cw_malloc(size) cw_realloc(NULL, size)
cw_inline void *cw_realloc(void *ptr, size_t size)
{
    if ((ptr = realloc(ptr, size)) == NULL) {
        fprintf (stderr, "cannot allocate %ld bytes, aborting.", (long) size);
        abort();
    }

    return ptr;
}

#define TINY_MASK(x)  (((u_int32_t)1<<(x))-1)
#define MASK_16 (((u_int32_t)1<<16)-1)
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)
#define FNV_32_PRIME  ((uint32_t)0x01000193)
#define strhash(s) fnv_32_hash(s)
#define fnv_32_str(s) fnv_32_hash(s)

/* fnv_32_str - perform a 32 bit Fowler/Noll/Vo hash on a string */
static inline uint32_t fnv_32_hash(char *str)
{
    uint32_t hval;
    unsigned char *s = (unsigned char *)str;        /* unsigned string */

    hval = FNV1_32A_INIT;
    while (*s) {
        hval ^= (uint32_t)*s++;
        hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    }

    return hval;
}

/* the modified Bernstein hash, return an odd number for double hash */
static inline unsigned int bernstein_hash(char *key)
{
    unsigned char *s = (unsigned char *) key;
    unsigned int h = 0;

    while (*s)
        h = 33 * h ^ *s++;
    //for(i = 0; i < keylen; i++)
        //h = 33 * h ^ p[i];

    return h % 2 ? h : h + 1;
}

/* get n(size) bytes of random data, store begin at ptr */
static inline int getrandom_n(void *ptr, size_t size)
{
    int fd, nread;

    fd = open("/dev/urandom", O_RDONLY);
    nread = read(fd, ptr, size);

    return nread;
}

