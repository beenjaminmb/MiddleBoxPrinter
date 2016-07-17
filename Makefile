RM=rm
CC=gcc
CFLAGS=-O0 -g  -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c scanner.c packet.c util.c

default : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner
