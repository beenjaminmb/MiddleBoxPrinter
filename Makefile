RM=rm
CC=gcc
CFLAGS=-O0 -Wall -g -std=gnu99
#CFLAGS=-O3 -Wall -std=gnu99 -fomit-frame-pointer
#CFLAGS=-O3 -Wall -std=gnu99 -fomit-frame-pointer -mtune=core2

LDLIBS=-pthread -lpcap

targets = main.c

default : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner
