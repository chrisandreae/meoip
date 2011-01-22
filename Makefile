VERSION=0.2

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -Werror -O0
LDFLAGS=$(DEBUG)

OBJS=meoip.o minIni.o

all: meoip

meoip: $(OBJS)

install: meoip
	cp meoip /usr/sbin

clean:
	rm -f $(OBJS) meoip core a.out gmon.out
