VERSION=0.3

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O3
LDFLAGS=$(DEBUG) -lpthread

OBJS=meoip.o minIni.o
OBJSVIP=vip.o minIni.o

all: meoip vip

meoip: $(OBJS)
vip: $(OBJSVIP)

install: meoip
	cp meoip /usr/sbin

clean:
	rm -f $(OBJS) meoip core a.out gmon.out
