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
                    # print dst, src, ttl
                    if src == "64.106.82.6" and ((src, dst) not in data):
                        data[(src, dst)] = [[], []]
                    elif src == "64,106.82.6":
                        data[(dst, src)][0] += [(ts, ttl)]
                    elif dst == "64.106.82.6":
                        if (dst, src) not in data:
                            data[(dst, src)][1] = []
                        data[(dst, src)][1] += [(ttl, ts)]

            except Exception as e:
                pass  # print e
    for (dst, src) in data:
        d = data[(dst, src)]
        print dst, src, "foo", d


def main():
    """ """
    process_pcap()

if __name__ == '__main__':
    main()
