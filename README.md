#MiddleBoxPrinter


##Overview

This project is, for now, a simple packet scanner/sniffer that 
sends out a bunch of packets to random IPv4 addresses. TTLs are 
modulated in an attempt to illicite distinguishing behavior
in middle boxes.

The scanner creates #CPU workers that each open a RAW socket.
The workers then generate packets and send them out. The goal
is for the total rate of packets sent out by all workers
to be equal to approximately 1Gb/sec. 

###Supported L3 Protocols

This program only supports IPv4 at this time.

###Supported L4 Protocols

This program supports TCP, UDP, and ICMP protocols.


###Building & Running

Type:

$ make

This will generate the program, ''scanner".

Then type:

$ sudo ./scanner 

to run the program in its default configuration. It currently
does not support runtime configuration from the command line but that will change.

Note that because this program uses raw sockets and requires that the network interface
be in promiscuous mode, you must be root. 

###NOTE
I might switch the code base to Golang at some point but for now we are
doing this thing in C FTW.