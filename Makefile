RM=rm
CC=gcc
CFLAGS=-O3 -Wall -std=gnu99
#CFLAGS=-O3 -Wall -std=gnu99 -fomit-frame-pointer
#CFLAGS=-O3 -Wall -std=gnu99 -fomit-frame-pointer -mtune=core2

LDLIBS=-pthread -lpcap

targets = main.c
unittests = unit_tests.c

default : 
	cd ./src
	$(MAKE)


unittest : $(unittests) 
	$(CC) $(CFLAGS) -o unittests $(unittests) $(LDLIBS)

clean :
	$(RM) -f *~ *.o core scanner unittests
