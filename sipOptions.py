from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dst", default="192.168.0.140", help="The destination IP")
parser.add_argument("-s", "--src", default="192.168.0.11", help="The source IP")
parser.parse_args()
args = parser.parse_args()

srcPort, dstPort = 5060, 5060   # 5060 is deafult SIP port

dstIp = args.dst
srcIp = args.src

sip = (
    'OPTIONS sip:{2}:{3};transport=udp SIP/2.0\r\n'
    'Via: SIP/2.0/UDP {0}:{1};branch=1234\r\n'
    'From: \"somedevice\"<sip:somedevice@{0}:{1}>;tag=5678\r\n'
    'To: <sip:{2}:{3}>\r\n'
    'Call-ID: 9abcd\r\n'
    'CSeq: 1 OPTIONS\r\n'
    'Max-Forwards: 0\r\n'
    'Content-Length: 0\r\n\r\n').format(srcIp, srcPort, dstIp, dstPort)


pkt = IP(src=srcIp, dst=dstIp)/UDP(sport=srcPort, dport=dstPort)/sip

send(pkt)