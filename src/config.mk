TARGET ?= default

############################################################################

define showhelp =
@echo "Supported targets are:"
@echo "   x86_64-uclibc"
@echo "   i686-uclibc"
@echo ""
@echo "Run as: make TARGET=<target name>"
endef

ifeq ($(TARGET), default)
    ICONV := 1
    OPTIMIZE_SIZE := 0
    CROSS := 

else ifeq ($(TARGET), x86_64-uclibc)
    STATIC := 1
    ICONV := 0
    OPTIMIZE_SIZE := 1
    CROSS ?= x86_64-pc-linux-uclibc-
    USE_PTHREADS = 0

else ifeq ($(TARGET), i686-uclibc)
    STATIC := 1
    ICONV := 0
    OPTIMIZE_SIZE := 1
    CROSS ?= i686-pc-linux-uclibc-
    USE_PTHREADS = 0

else
default:
	@echo "unknown compile target: $(TARGET)"
	@echo
	@$(showhelp)
endif

# some defaults
MEMDEBUG ?= 0
DEBUG ?= 0
STATIC ?= 0
USE_PTHREADS ?= 1

############################################################################

CC = $(CROSS)gcc

CFLAGS = -pipe
CFLAGS += -g $(OPT_FLAGS) $(CDEFINES)
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused
CFLAGS += -fvisibility=hidden -fPIC -fpic -fpie -pie
CFLAGS += -I$(TOPDIR)iniparser/src/ -I$(TOPDIR)libev/ -I$(TOPDIR)libebb/

EV_CFLAGS ?= -DEV_USE_EPOLL=1 -DEV_USE_SELECT=1

LD = $(CC)
LDFLAGS = -Wl,--as-needed
LDLIBS =

CDEFINES = -D_GNU_SOURCE

ifneq ($(USE_PTHREADS), 0)
    CFLAGS += -pthread
    LDLIBS += -lpthread
    CDEFINES += -DUSE_PTHREADS
endif

ifneq ($(STATIC), 0)
    LDFLAGS += -static
endif

ifeq ($(DEBUG), 0)
    LDFLAGS += -s
endif

ifneq ($(OPTIMIZE_SIZE), 0)
    OPT_FLAGS = -Os
else
    OPT_FLAGS = -O2
endif

ifeq ($(OPTIMIZE_SIZE), 0)
    CDEFINES += -DHT_INLINE
endif

ifneq ($(ICONV), 0)
    CDEFINES += -DHAVE_ICONV
endif

ifneq ($(DEBUG), 0)
    CDEFINES += -DDEBUG
else
    CDEFINES += -DNDEBUG
endif

ifneq ($(MEMDEBUG), 0)
    CFLAGS += -DMALLOC_DEBUG  -fno-inline
    LDLIBS += /usr/lib/libduma.a
endif

RM = rm -f

AR = $(CROSS)ar
ARFLAGS = rcv
RANLIB = $(CROSS)ranlib
