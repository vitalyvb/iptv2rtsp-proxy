TOPDIR=./
include $(TOPDIR)config.mk

VERSION:=0.1

CFLAGS += -DVERSION=\"$(VERSION)\"

######################################################################

SUFFIXES = .o .c .h

COMPILE.c=$(CC) $(CFLAGS) -c
.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

HEADERS = global.h config.h psi.h stats.h utils.h jhash.h mpeg_tbl.h rtspproto.h

SRCS = server.c \
       mpegio.c \
       utils.c \
       jhash.c \
       ht.c \
       rng.c \
       csconv.c \
       psi.c \
       rtsp.c \
       rtspproto.c

OBJS = $(SRCS:.c=.o)

default: iptv2rtsp-proxy

ht.o: ht.c ht.h

iptv2rtsp-proxy: $(OBJS) iniparser/libiniparser.a libev/libev.a libebb/libebb.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

iniparser/libiniparser.a:
	make -C iniparser libiniparser.a

libebb/libebb.a:
	make -C libebb libebb.a

libev/libev.a:
	make -C libev libev.a

clean:
	$(RM) *.o iptv2rtsp-proxy

cleanall:
	make -C iniparser veryclean
	make -C libebb clean
	make -C libev clean
	$(RM) *.o iptv2rtsp-proxy

.PHONY: default clean cleanall
