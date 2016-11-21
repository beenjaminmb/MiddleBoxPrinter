RM=rm
CC=gcc
CFLAGS=-O0 -g -Wall -std=gnu99
DIST_FLAGS=-O0 -g -Wall -std=gnu99
LDLIBS=-pthread -lpcap -lm

targets = main.c dtable.c scanner.c sniffer.c ssocket.c blacklist.c constraint.c logger.c lockfd.c xalloc.c util.c

test_scanner = test_scanner.c dtable.c scanner.c sniffer.c ssocket.c blacklist.c constraint.c logger.c lockfd.c xalloc.c util.c 

tablesrc = test_dict.c dtable.c

testpcap = test_pcap_reader.c dtable.c scanner.c sniffer.c ssocket.c blacklist.c constraint.c logger.c lockfd.c xalloc.c util.c

SKYTHE=sc-ythe

all : dist_dillinger test_scanner test_pcap_reader test_dict

dist : $(targets)
	$(CC) $(CFLAGS) -o scanner $(targets) $(LDLIBS)

dist_dillinger : $(targets)
	$(CC) -DDILLINGER $(DIST_FLAGS) -o $(SKYTHE) $(targets) $(LDLIBS)

vmscanner : $(targets)
	$(CC)  -O0 -std=gnu99 -DUNITTEST=1 -o vmscanner $(targets) $(LDLIBS)

test_scanner_dil : $(test_scanner)
	$(CC) -DDILLINGER $(CFLAGS) -o test_scanner $(test_scanner) $(LDLIBS)

test_scanner : $(test_scanner)
	$(CC) $(CFLAGS) -o test_scanner $(test_scanner) $(LDLIBS)


test_pcap_reader_dill : $(testpcap)
	$(CC) -DDILLINGER $(CFLAGS) -o test_pcap_reader $(testpcap) $(LDLIBS)

test_pcap_reader: $(testpcap)
	$(CC) $(CFLAGS) -o test_pcap_reader $(testpcap) $(LDLIBS)



test_dict: $(tablesrc)
	$(CC) $(CFLAGS) -o test_table $(tablesrc)

clean:
	rm -f vmscanner scanner *~ test_table core test_pcap_reader test_scanner $(SKYTHE)
