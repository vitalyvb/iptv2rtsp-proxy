
CROSS =
CC = $(CROSS)gcc

CFLAGS = -pipe
CFLAGS += -g -O2
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused
CFLAGS += -D_GNU_SOURCE -pthread
CFLAGS += -fvisibility=hidden -fPIC -fpic -fpie -pie
CFLAGS += -I$(TOPDIR)iniparser/src/ -I$(TOPDIR)libev/ -I$(TOPDIR)libebb/

EV_CFLAGS += -DEV_USE_EPOLL=1 -DEV_USE_SELECT=1

LD = $(CC)
LDFLAGS = -Wl,--as-needed
LDLIBS = -lpthread

#CFLAGS += -DNDEBUG
CFLAGS += -DDEBUG

#CFLAGS += -DMALLOC_DEBUG  -fno-inline
#LDLIBS += /usr/lib/libduma.a

RM = rm -f

AR = $(CROSS)ar
ARFLAGS = rcv
RANLIB = $(CROSS)ranlib
