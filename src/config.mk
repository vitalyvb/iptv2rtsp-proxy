
CROSS =
CC = $(CROSS)gcc

CFLAGS = -pipe -march=k8
CFLAGS += -g -O0 -fPIC -I$(TOPDIR)iniparser/src/ -I$(TOPDIR)libev/ -I$(TOPDIR)libebb/
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused
CFLAGS += -D_GNU_SOURCE -pthread
CFLAGS += -fvisibility=hidden -fPIC -fpic -fpie -pie
EV_CFLAGS += -DEV_USE_EPOLL=1 -DEV_USE_SELECT=1

LD = $(CC)
LDFLAGS = -Wl,--as-needed
LDLIBS = -lpthread

#CFLAGS += -DNDEBUG

CFLAGS += -DDEBUG
CFLAGS += -DMALLOC_DEBUG  -fno-inline
LDLIBS += /usr/lib/libduma.a

RM = rm -f

AR = $(CROSS)ar
ARFLAGS = rcv
RANLIB = $(CROSS)ranlib
