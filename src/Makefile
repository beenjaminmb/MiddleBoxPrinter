RM=rm
CC=gcc
CFLAGS=-O0 -g -Wall -std=gnu99

LDLIBS=-pthread -lpcap

targets = main.c dtable.c scanner.c sniffer.c
test_scanner = test_scanner.c
tablesrc = test_dict.c dtable.c
testpcap = test_pcap_reader.c dtable.c scanner.c sniffer.c blacklist.c constraint.c logger.c lockfd.c xalloc.c util.c

dist : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

dist_dillinger : $(targets)
	$(CC) -DDILLINGER -Wall -std=gnu99 -O3 -o scanner $(targets) $(LDLIBS)


vmscanner : $(targets)
	$(CC)  -O0 -std=gnu99 -DUNITTEST=1 -o vmscanner $(targets) $(LDLIBS)

test_dillinger : $(targets)
	$(CC) -DUNITTEST -DDILLINGER $(CFLAGS) -o scanner $(targets) $(LDLIBS)

test_pcap_reader: $(testpcap)
	$(CC) $(CFLAGS) -o test_pcap_reader $(testpcap) $(LDLIBS) -lm

test_dict: $(tablesrc)
	$(CC) $(CFLAGS) -o test_table $(tablesrc)

clean:
	rm -f vmscanner scanner *~ test_table core test_pcap_reader
