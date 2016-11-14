RM=rm
CC=gcc
CFLAGS=-O0 -g -Wall -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c
unittests = unit_tests.c
test_dict = test_dict.c

dist : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

dist_dillinger : $(targets)
	$(CC) -DDILLINGER $(CFLAGS) -o scanner $(targets) $(LDLIBS)

vmscanner : $(targets)
	$(CC)  -O0 -std=gnu99 -DUNITTEST=1 -o vmscanner $(targets) $(LDLIBS)


all:
	${CC}

dict: $(test_dict) 
	$(CC)  $(CFLAGS) -o test_dict $(test_dict) 

clean:
	rm -f vmscanner scanner *~ test_dict core
