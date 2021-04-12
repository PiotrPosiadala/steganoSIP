from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-dst", default="192.168.0.140", help="The destination IP")
parser.add_argument("-src", default="192.168.0.11", help="The source IP")
parser.parse_args()
args = parser.parse_args()

srcPort, dstPort = 5060, 5060   # 5060 is deafult SIP port

print(args.src)

dstIp = args.dst
srcIp = args.src

sip = (
    'OPTIONS sip:{0}:5060;transport=udp SIP/2.0\r\n'
    'Via: SIP/2.0/TCP 192.168.44.32:5060;branch=1234\r\n'
    'From: \"somedevice\"<sip:somedevice@1.1.1.1:5060>;tag=5678\r\n'
    'To: <sip:{0}:5060>\r\n'
    'Call-ID: 9abcd\r\n'
    'CSeq: 1 OPTIONS\r\n'
    'Max-Forwards: 0\r\n'
    'Content-Length: 0\r\n\r\n').format(dstIp)


pkt = IP(src=srcIp, dst=dstIp)/UDP(sport=srcPort, dport=dstPort)/sip

send(pkt)