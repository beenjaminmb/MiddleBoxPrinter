RM=rm
CC=gcc
CFLAGS=-O3 -Wall -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c
unittests = unit_tests.c

dist : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

vmscanner : $(targets)
	$(CC)  -O0 -std=gnu99 -DUNITTEST=1 -o vmscanner $(targets) $(LDLIBS)


all:
	${CC}

clean:
	rm -f vmscanner scanner *~
