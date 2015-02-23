
CC = gcc
CFLAGS = -Wall -O2
LIBS =

BLACKSOCKS = blacksocks


# default target
.PHONY : all
all: $(BLACKSOCKS)
	@echo all done!

OBJS =
OBJS += dns.o
OBJS += option.o
OBJS += cache.o
OBJS += common.o

BLACKSOCKS_OBJS = $(OBJS)
BLACKSOCKS_OBJS += blacksocks.o

dns.o: utils.c dns.c common.h
option.o: option.c common.h
blacksocks.o: utils.c blacksocks.c common.h
cache.o: utils.c cache.c common.h
common.o: common.c common.h

$(BLACKSOCKS): $(BLACKSOCKS_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

install: all
	cp blacksocks /usr/local/bin/
	cp debian/blacksocks.conf /etc/
	cp debian/blacksocks.init /etc/init.d/blacksocks
	cp debian/blacksocks.logrotate.d /etc/logrotate.d/blacksocks

.PHONY : clean
clean:
	rm -f *.o core a.out $(BLACKSOCKS)
