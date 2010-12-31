VERSION=0.1

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O0
LDFLAGS=$(DEBUG)

OBJS=meoip.o

all: meoip

meoip: $(OBJS)

install: meoip
	cp meoip /usr/sbin

clean:
	rm -f $(OBJS) meoip core a.out gmon.out
