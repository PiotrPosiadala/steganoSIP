import base64
import random
import time
from scapy.all import *
import argparse
import secrets as s
from scapy.layers.inet import UDP
from scapy.layers.inet import IP


def sip_options():
    '''
    SIP Options message without covert channel
    '''
    rand_list = [22, 25, 28]
    return (
        'OPTIONS sip:terminal01121605@pw.edu.pl;transport=udp SIP/2.0\r\n'
        'Via: SIP/2.0/UDP sbcwaw1@pw.edu.pl;branch={0}\r\n'
        'From: \"presenceserverwaw1\"<sip:presenceserverwaw1@pw.edu.pl>;tag={1}\r\n'
        'To: <sip:terminal01121605@pw.edu.pl>\r\n'
        'Call-ID: {2}@pw.edu.pl\r\n'
        'CSeq: {3} OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        'Call-Info: Please, let me know about your avability.\r\n'
        'Organization: Warsaw University of Technology, Faculty of Electronics and Information Technology \r\n'
        'Content-Length: 0\r\n\r\n').format('z9hG4bK' + s.token_urlsafe(5), s.token_urlsafe(8), s.token_urlsafe(24),
                                            s.randbits(random.choice(rand_list)))


def stegano_sip_options(msg):
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
        'Call-Info: Please, let me know about your availability\r\n'
        'Organization: {4} \r\n'
        'Content-Length: 0\r\n\r\n').format('z9hG4bK' + msg[:5], s.token_urlsafe(8), s.token_urlsafe(24),
                                            s.randbits(16), msg[5:])


def go_go_sip(args):
    dst_ip = args.dst
    src_ip = args.src
    covert = args.covert
    file_name = args.file
    src_port, dst_port = 5060, 5061  # 5060 is default SIP port

    file = open(file_name, "r")
    data = file.read()

    for i in range(0, len(data), 20):
        msg = base64.urlsafe_b64encode(bytes(data[i:i + 20], 'utf-8'))
        msg = msg.decode('utf-8')

        if msg[-2:] == "==":
            msg = msg[0:-2]
        elif msg[-1:] == "=":
            msg = msg[0:-1]

        if covert:
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / stegano_sip_options(msg)
        else:
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / sip_options()
        send(pkt)
        time.sleep(1)

    file.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dst", default="192.168.0.11", help="The destination IP")
    parser.add_argument("-s", "--src", default="192.168.0.11", help="The source IP")
    parser.add_argument("-c", "--covert", action="store_true", default=True,
                        help="Generating SIP Options with hidden info (covert channel)")
    parser.add_argument("-f", "--file", default="message.txt", help="File to hide in covert channel")
    parser.parse_args()
    args = parser.parse_args()

    go_go_sip(args)


if __name__ == '__main__':
    main()
