RM=rm
CC=gcc
CFLAGS=-O0 -g -std=gnu99

LDLIBS=-pthread

targets = main.c spoofer.c packet.c

default : $(targets)
	$(CC) $(CFLAGS) -o spoofer $(targets) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core spoofer
