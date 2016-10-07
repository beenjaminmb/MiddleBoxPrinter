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

    ip_meta_stats = {"len": {},
                     "id": {},
                     "off": {},
                     "ttl": {},
                     "p": {},
                     "sum": {},
                     "opts": {}}
    for () in ip:

        # len = 40,
        # id = 31942,
        # off = 16384,
        # ttl = 245,
        # p = 6,
        # sum = 20337,
        # src = '\xb4\xfar-',
        # dst = '@jR\x06',
        # opts = ''
        # ip_opts = {}
        # ip_seq = {}
        # ip_len = {}
        # ip_id = {}
        # ip_opt = {}

    hdr = ()
    return hdr


def process_ICMP(**kwargs):
    """ Process ICMP header: """

    icmp_stats = {"TimeExceed": [0, 0], "Redirect": [0, 0],
                  "Unreach": [0, 0], "Quench": [0, 0]}

    icmp_responses = kwargs["icmp_responses"]
    num_probes_responses = {}
    responder_origin = {}
    for (src, dst) in icmp_responses:
        # Source IP and Target IP
        num_probes = len(icmp_responses[(src, dst)])

        if num_probes not in num_probe_responses:
            path_lengths[path_len] = 0
        path_lengths[path_len] += 1
        new_msg = True
        for (psrc, ip) in icmp_responses[(src, dst)]:  # Source IP and Target IP
            # psrc = Source of the probe response
            icmp = ip.data
            icmpdata = icmp.data
            path_lengths
            responder = socket.inet_ntoa(ip.src)
            if responder not in responder_origin:
                responder_origin[responder] = [0, {}]
            responder_origin[responder][0] == 1
            icmpdata = icmp.data
            probe = icmpdata.data
            newdst = socket.inet_ntoa(probe.dst)
            newsrc = socket.inet_ntoa(probe.src)

            if newdst not in responder_origin[responder][1]:
                responder_origin[responder][1][newdst] = 0
            responder_origin[responder][1][newdst] += 1

            if isinstance(icmpdata, dpkt.icmp.ICMP.TimeExceed):
                """ """
                icmp_stats["TimeExceed"][0] += 1
                if new_msg:
                    new_msg = False
                    icmp_stats["TimeExceed"][1] += 1
            elif isinstance(icmpdata, dpkt.icmp.ICMP.Redirect):
                """ """
                icmp_stats["Redirect"][0] += 1
                if new_msg:
                    new_msg = False
                    icmp_stats["Redirect"][1] += 1

            elif isinstance(icmpdata, dpkt.icmp.ICMP.Unreach):
                """ """
                icmp_stats["Unreach"][0] += 1
                if new_msg:
                    new_msg = False
                    icmp_stats["Unreach"][1] += 1

            elif isinstance(icmpdata, dpkt.icmp.ICMP.Quench):
                """ """
                icmp_stats["Quench"][0] += 1
                if new_msg:
                    new_msg = False
                    icmp_stats["Quench"][1] += 1

    print "Path Length distribution:"
    for p in path_lengths:
        print "\t", p, path_lengths[p]

    print "ICMP Response message type distribution:"
    for typee in icmp_stats:
        print "\t", typee, icmp_stats[typee]

    print "Response Stats:"
    for responder in responder_origin:
        print "\t Responder: %s %s" % (responder, responder_origin[responder][0])
        for newdst in responder_origin[responder][1]:
            print "\t\tTarget: %s, #probes %s" % (newdst, responder_origin[responder][1][newdst])


def process_TCP(**kwargs):
    """ Process ICMP header: """
    tcp_responses = kwargs["tcp_responses"]
    icmp_replies = kwargs["icmp_replies"]
    tcp_flags = {}
    tcp_off = {}

    tcp_meta_stats {"sport": {},
                    "seq": {},
                    "ack": {},
                    "flags": {},
                    "win": {},
                    "sum": {},
                    "opts": {}}

    for (src, dst) in tcp_responses:
        print "TCP Probe:", src, dst
        for (psrc, probe) in tcp_responses[(src, dst)]:
            print "\tTCP response", psrc, probe.sport, probe.seq, probe.ack, probe.flags, probe.win, probe.sum, probe.opts


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
                                    (newsrc, newdst)] += [(src, ip)]
                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Unreach):
                                """ """
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, ip)]
                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Quench):
                                """ """
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, ip)]

                            elif isinstance(icmpdata, dpkt.icmp.ICMP.Redirect):
                                probe = icmpdata.data
                                newdst = socket.inet_ntoa(probe.dst)
                                newsrc = socket.inet_ntoa(probe.src)
                                if (newsrc, newdst) not in icmp_responses:
                                    icmp_responses[(newsrc, newdst)] = []
                                icmp_responses[
                                    (newsrc, newdst)] += [(src, ip)]

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
