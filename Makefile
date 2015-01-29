
CC = gcc
CFLAGS = -Wall -g
LIBS =

BLACKSOCKS = blacksocks


# default target
.PHONY : all
all: $(BLACKSOCKS)
	@echo all done!

OBJS =
OBJS += dns.o
OBJS += cache.o
OBJS += common.o


BLACKSOCKS_OBJS = $(OBJS)
BLACKSOCKS_OBJS += socks5.o

dns.o: utils.c dns.c dns.h
socks5.o: utils.c socks5.c socks5.h
#connect.o: connect.c connect.h
cache.o: utils.c cache.c cache.h
common.o: common.c common.h


$(BLACKSOCKS): $(BLACKSOCKS_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

.PHONY : clean
clean:
	rm -f *.o core a.out $(BLACKSOCKS)
