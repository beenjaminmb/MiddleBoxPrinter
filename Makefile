RM=rm
CC=gcc
CFLAGS=-O3 -std=gnu99

LDLIBS=-pthread

targets = main.c scanner.c packet.c util.c

default : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner
