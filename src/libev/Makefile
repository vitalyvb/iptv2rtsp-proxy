TOPDIR=../
include $(TOPDIR)config.mk

CFLAGS += -D_GNU_SOURCE $(EV_CFLAGS) -DEV_STANDALONE=1 -Wno-extra

#############################################################

SUFFIXES = .o .c .h

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

SRCS = ev.c

OBJS = $(SRCS:.c=.o)

default: libev.a

ev.c: ev.h

libev.a: $(OBJS)
	$(AR) rs $@ $^

clean:
	$(RM) *.o libev.a
