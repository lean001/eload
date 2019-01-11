CC = gcc -g -O0 -W
LDFLAGS = -lpthread
#INSTALLDIR = /usr/local/lib
#INCLUDEDIR = /usr/local/include

EXE := eload

OBJS = eload.o util-epoll.o \
util-http.o

SOURCES = eload.c eload.h \
util-epoll.c util-epoll.h \
util-http.c util-http.h



all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(OBJS) -o $(EXE) $(LDFLAGS)

*.o:*.c

test: $(EXE)


install: $(EXE)
	cp $(EXE) $(INSTALLDIR) 

uninstall:
	rm -f $(INSTALLDIR)/$(EXE)
clean:
	rm -f  $(EXE) $(OBJS) test

.PHONY: all install clean test

