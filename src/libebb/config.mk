
# libev
EVINC  = ../libev/
EVLIB  = ../libev/
EVLIBS = -L${EVLIB} -lev

# includes and libs
INCS = -I${EVINC}
LIBS = ${EVLIBS}
# -lefence

# flags
CPPFLAGS = -DVERSION=\"$(VERSION)\"
LDFLAGS  = -s ${LIBS}
LDOPT    = -shared
SUFFIX   = so
SONAME   = -Wl,-soname,$(OUTPUT_LIB)

# Solaris
#CFLAGS  = -fast ${INCS} -DVERSION=\"$(VERSION)\" -fPIC
#LDFLAGS = ${LIBS}
#SONAME  = 

# Darwin
# LDOPT  = -dynamiclib 
# SUFFIX = dylib
# SONAME = -current_version $(VERSION) -compatibility_version $(VERSION)

