from scapy.all import *
import argparse
import secrets as s
import time

'''
sipOptions
Simple SIP agent sending SIP Options messages 
containing or not coverted informations
'''

def sip_options():
    '''
    SIP Options message witout covert channel
    '''
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


def stegano_sip_options(gen):
    ''' 
    SIP Options message with covert channel
    '''
    return (
        'OPTIONS sip:terminal01121605@pw.edu.pl;transport=udp SIP/2.0\r\n'
        'Via: SIP/2.0/UDP sbcwaw1@pw.edu.pl;branch={0}\r\n'
        'From: \"presenceserverwaw1\"<sip:presenceserverwaw1@pw.edu.pl>;tag={1}\r\n'
        'To: <sip:terminal01121605@pw.edu.pl>\r\n'
        'Call-ID: {2}@pw.edu.pl\r\n'
        'CSeq: {3} OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        'Call-Info: Please, let me know about your avability\r\n'
        'Organization: {4} \r\n'
        'Content-Length: 0\r\n\r\n').format(s.token_urlsafe(8), s.token_urlsafe(8), s.token_urlsafe(24), s.randbits(16), next(gen))

def get_line(file_name):
    '''
    Receiving next line of the file every time this generator is called
    '''
    for line in open(file_name, "r"):
        yield line


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dst", default="192.168.0.11", help="The destination IP")
parser.add_argument("-s", "--src", default="192.168.0.11", help="The source IP")
parser.add_argument("-c", "--covert", action="store_true", default=False, help="Generating SIP Options with hidden info (covert channel)")
parser.add_argument("-f", "--file", default="message.txt", help="File to hide in covert channel")
parser.parse_args()
args = parser.parse_args()

dst_ip = args.dst
src_ip = args.src
covert = args.covert
file_name = args.file

src_port, dst_port = 5060, 5061    # 5060 is deafult SIP port
line_gen = get_line(file_name)     # generator for reading lines of file


if covert: 
    pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/stegano_sip_options(line_gen)
else:
    pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/sip_options()

send(pkt)