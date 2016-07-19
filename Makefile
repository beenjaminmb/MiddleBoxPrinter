RM=rm
CC=gcc
CFLAGS=-O3 -Wall -g  -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c scanner.c packet.c

default : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner
