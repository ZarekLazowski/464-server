CC = gcc
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  json-server-$(EXEC_SUFFIX)

json-server-$(EXEC_SUFFIX): json-server.o smartalloc.o
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ json-server.o smartalloc.o

json-server.o: json-server.c json-server.h
	$(CC) $(CFLAGS) -c json-server.c json-server.h

smartalloc.o: smartalloc.c smartalloc.h
	$(CC) $(CFLAGS) -c smartalloc.c smartalloc.h

handin: README
	handin bellardo 464_fp README smartalloc.c smartalloc.h json-server.c json-server.h Makefile

clean:
	rm -rf json-server-* json-server-*.dSYM *.o *.gch *~
