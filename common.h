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

#endif
