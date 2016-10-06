#!/usr/bin/env python
import dpkt as dpkt
import matplotlib as plt
import numpy as np
import socket
PCAP_FILE = 'prac2.pcap'
SPOOF_IP = "64.106.82.6"


def process_IP(**kwargs):
    """ 
    Process IP header:
    """
    ip = kwargs["ip"]
    hdr = ()
    return hdr


def process_ICMP(**kwargs):
    """ Process ICMP header: """
    icmp_responses = kwargs["icmp_responses"]
    for (src, dst) in icmp_responses:
        for (psrc, probe) in icmp_responses[(src, dst)]:
            print "\t", src, dst, probe


def process_TCP(**kwargs):
    """ Process ICMP header: """
    tcp_responses = kwargs["tcp_responses"]
    for (src, dst) in tcp_responses:
        for (psrc, probe) in tcp_responses[(src, dst)]:
            print "\t", src, dst, probe


def process_pcap(**kwargs):
    """ """
    data = {}
    stats = {}
    icmp_responses = {}
    tcp_responses = {}
    udp_responses = {}
    other_responses = {}
    response_types = {""}
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

                    if src == SPOOF_IP:
                        if (src, dst) not in data:
                            data[(src, dst)] = [[(ts, ttl)], []]

                        elif (src, dst) in data:
                            data[(src, dst)][0] += [(ts, ttl)]

                        if (src, dst) not in stats:
                            stats[(src, dst)] = [1, 0]

                        elif (src, dst) in stats:
                            stats[(src, dst)][0] += 1

                    elif dst == SPOOF_IP:
                        if isinstance(ip.data, dpkt.icmp.ICMP):
                            icmp = ip.data
                            icmpdata = icmp.data
                            if isinstance(icmpdata, dpkt.icmp.ICMP.TimeExceed):
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, probe)]
                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Unreach):
                                """ """
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, probe)]
                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Quench):
                                """ """
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, probe)]

                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Redirect):
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, probe)]

                        elif isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            tcp = tcp.unpack
                            if (dst, src) not in tcp_responses:
                                tcp_responses[(src, dst)] = []
                            tcp_responses[
                                (src, dst)] += [(src, ip)]

                        elif isinstance(ip.data, dpkt.udp.UDP):
                            """ """
                            udp = ip.data
                            udp = tcp.unpack
                            if (dst, src) not in udp_responses:
                                udp_responses[(src, dst)] = []
                            udp_responses[
                                (src, dst)] += [(src, ip)]

                        else:
                            """ """
                            if (dst, src) not in other_responses:
                                other_responses[(src, dst)] = []
                            other_responses[
                                (src, dst)] += [(src, ip)]

                elif isinstance(eth.data, dpkt.arp.ARP):
                    pass
                elif isinstance(eth.data, dpkt.stp.STP):
                    pass
                elif isinstance(eth.data, dpkt.llc.LLC):
                    pass
                else:
                    pass
                    # print "Other L3", eth.unpack
            except Exception as ex:
                template = "An exception of type {0} occured. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                print message, ttl, ts

    import datetime
    ctime = lambda t: str(datetime.datetime.fromtimestamp(
        int(t)).strftime('%Y-%m-%d %H:%M:%S'))

    process_ICMP(icmp_responses=icmp_responses)
    process_TCP(tcp_responses=tcp_responses)

    # for (src, dst) in icmp_responses:
    #     print "ICMP Responses: ", src, dst, len(icmp_responses[(src, dst)])

    # for (src, dst) in tcp_responses:
    #     print "TCP Responses: ", src, dst, len(tcp_responses[(src, dst)])

    # for (src, dst) in udp_responses:
    #     print "UDP Responses: ", src, dst, len(udp_responses[(src, dst)])

    # for (src, dst) in other_responses:
    #     print "Other Responses: ", src, dst, len(other_responses[(src, dst)])
    # for (dst, src) in data:
    #     d1 = data[(dst, src)][0]
    #     d2 = data[(dst, src)][1]
    #     if len(d1) > 0 and len(d2) > 0:
    #         print "Replys ", dst, src, len(d1), len(d2)
    #         for a in d1:
    #             print "\tProbe:", ctime(a[0]), a[1]
    #         for b in d2:
    #             print "\tResponse: ", ctime(b[0]), b[1]

    # request_hist = {}
    # reply_hist = {}
    # for (src, dst) in stats:
    #     if stats[(src, dst)][0] not in request_hist:
    #         request_hist[stats[0]] = 0
    #     if stats(src, dst)[3] not in reply_hist:
    #         request_hist[stats[0]] = 0


def main():
    """ """
    process_pcap()

if __name__ == '__main__':
    main()
