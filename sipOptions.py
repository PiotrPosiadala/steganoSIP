from scapy.all import *
import argparse
import secrets as s

def sip_options():
    return (
        'OPTIONS sip:terminal01121605@pw.edu.pl;transport=udp SIP/2.0\r\n'
        'Via: SIP/2.0/UDP sbcwaw1@pw.edu.pl;branch={0}\r\n'
        'From: \"presenceserverwaw1\"<sip:presenceserverwaw1@pw.edu.pl>;tag={1}\r\n'
        'To: <sip:terminal01121605@pw.edu.pl>\r\n'
        'Call-ID: {2}@pw.edu.pl\r\n'
        'CSeq: {3} OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        'Call-Info: Please, let me know about your avability\r\n'
        'Organization: Warsaw University of Technology, Faculty of Electronics and Information Technology \r\n'
        'Content-Length: 0\r\n\r\n').format(s.token_urlsafe(8), s.token_urlsafe(8), s.token_urlsafe(24), s.randbits(16))

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dst", default="192.168.0.140", help="The destination IP")
parser.add_argument("-s", "--src", default="192.168.0.11", help="The source IP")
parser.parse_args()
args = parser.parse_args()

dst_ip = args.dst
src_ip = args.src

src_port, dst_port = 5060, 5060   # 5060 is deafult SIP port

pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/sip_options()

send(pkt)