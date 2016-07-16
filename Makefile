RM=rm
CC=gcc
CFLAGS=-O0 -g -std=gnu99

LDLIBS=-pthread

targets = main.c scanner.c packet.c

default : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner
