TOPDIR=./
include $(TOPDIR)config.mk

VERSION:=0.2.3

CFLAGS += -DVERSION=\"$(VERSION)\"

######################################################################

SUFFIXES = .o .c .h

COMPILE.c=$(CC) $(CFLAGS) -c
.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

HEADERS = config.h csconv.h global.h ht.h httpsess.h jhash.h mpegio.h \
	  mpeg_tbl.h psi.h rtcp.h rtp.h rtsp.h rtspproto.h rtspsess.h \
	  url.h utils.h

SRCS = server.c \
       mpegio.c \
       utils.c \
       jhash.c \
       ht.c \
       rng.c \
       csconv.c \
       psi.c \
       rtsp.c \
       rtspsess.c \
       httpsess.c \
       url.c \
       rtcp.c \
       rtspproto.c

OBJS = $(SRCS:.c=.o)

default: iptv2rtsp-proxy

help:
	@$(showhelp)

ht.o: ht.c ht.h

iptv2rtsp-proxy: $(OBJS) iniparser/libiniparser.a libev/libev.a libebb/libebb.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

iniparser/libiniparser.a:
	$(MAKE) -C iniparser libiniparser.a

libebb/libebb.a:
	$(MAKE) -C libebb libebb.a

libev/libev.a:
	$(MAKE) -C libev libev.a

clean:
	$(RM) *.o iptv2rtsp-proxy

cleanall:
	$(MAKE) -C iniparser veryclean
	$(MAKE) -C libebb clean
	$(MAKE) -C libev clean
	$(RM) *.o iptv2rtsp-proxy

.PHONY: default help clean cleanall
