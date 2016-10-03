#!/usr/bin/env python
import dpkt as dpkt
import socket
PCAP_FILE = 'prac2.pcap'


def process_pcap(**kwargs):
    """ """
    data = {}
    with open(PCAP_FILE, 'r') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, frame in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(frame)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    dst = socket.inet_ntoa(ip.dst)
                    src = socket.inet_ntoa(ip.src)
                    ttl = ip.ttl
                    if src == "64.106.82.6":
                        print "Bar", src, dst
                        if not ((src, dst) in data):
                            data[(src, dst)] = [[(ts, ttl)], []]
                        elif ((src, dst) in data):
                            data[(src, dst)][0] += [(ttl, ts)]
                        else:
                            print "BooFar"

                    elif dst == "64.106.82.6":
                        print "Foo", src, dst

                    else:
                        print "FUCK", src, dst
                        # if src == map(ord, "64.106.82.6")) and not ((src, dst) in data):
                        #     data[(src, dst)] = [[(ts, ttl)], []]

                        # elif src == "64.106.82.6" and ((src, dst) in data):
                        #     data[(dst, src)][0] += [(ts, ttl)]

                        # if dst == "64.106.82.6":
                        #     if not ((dst, src) in data):
                        #         data[(dst, src)][1] = []
                        #         data[(dst, src)][1] += [(ttl, ts)]
                        #         print "if", src, dst
                        #     elif (dst, src) in data:
                        #         data[(dst, src)][1] += [(ttl, ts)]
                        #         print "elif", src, dst
                        #     else:
                        #         print "else", src, dst
                        # else:
                        #     src, dst
            except Exception as ex:
                template = "An exception of type {0} occured. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                print message, ttl, ts
    for (dst, src) in data:
        d1 = data[(dst, src)][0]
        d2 = data[(dst, src)][1]
        print dst, src, d1, d2


def main():
    """ """
    process_pcap()

if __name__ == '__main__':
    main()
