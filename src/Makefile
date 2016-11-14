RM=rm
CC=gcc
CFLAGS=-O0 -g -Wall -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c dtable.c scanner.c
unittests = unit_tests.c
tablesrc = test_dict.c dtable.c

dist : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

dist_dillinger : $(targets)
	$(CC) -DDILLINGER $(CFLAGS) -o scanner $(targets) $(LDLIBS)

vmscanner : $(targets)
	$(CC)  -O0 -std=gnu99 -DUNITTEST=1 -o vmscanner $(targets) $(LDLIBS)

test_dict: $(tablesrc)
	$(CC) $(CFLAGS) -o test_table $(tablesrc)

clean:
	rm -f vmscanner scanner *~ test_table core
