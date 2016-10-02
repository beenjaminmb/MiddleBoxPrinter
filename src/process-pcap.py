#!/usr/bin/env python
import dpkt as dpkt
import socket
PCAP_FILE = 'prac.pcap'


def main():
    """ """

    with open(PCAP_FILE, 'r') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, frame in pcap:
            eth = dpkt.ethernet.Ethernet(frame)
            ip = eth.data
            dst = socket.inet_ntoa(ip.dst)
            src = socket.inet_ntoa(ip.src)
            ttl = ip.ttl
            print dst, src, ttl
            pl = ip.data
if __name__ == '__main__':
    main()
