from scapy.all import *
import base64
import argparse
import secrets as s
from scapy.layers.inet import UDP
from scapy.layers.inet import IP

'''
sipOk
Simple SIP agent sniffing for SIP Options messages 
and replaying with SIP 200 OK message
'''


def get_call_id(sip):
    call_id_index = sip.find(b'Call-I') + 9
    call_id_end_index = sip.find(b'@', call_id_index)
    call_id = sip[call_id_index:call_id_end_index]
    call_id = call_id.decode('UTF-8')
    return str(call_id)


def get_via_branch(sip):
    branch_index = sip.find(b'branch=') + 14
    branch_end_index = sip.find(b'\r', branch_index)
    branch = sip[branch_index:branch_end_index]
    branch = branch.decode('UTF-8')
    return branch


def sip_ok(via_branch, call_id):
    print("sip_ok_generating")
    return (
        'SIP/2.0 200 OK\r\n'
        'Via: SIP/2.0/UDP sbcwaw1@pw.edu.pl;branch={0}\r\n'
        'From: <sip:terminal01121605@pw.edu.pl>\r\n'
        'To: \"presenceserverwaw1\"<sip:presenceserverwaw1@pw.edu.pl>\r\n'
        'Call-ID: {2}@pw.edu.pl\r\n'
        'CSeq: {3} OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        'Call-Info: I am avaiable\r\n'
        'Organization: Warsaw University of Technology, Faculty of Electronics and Information Technology \r\n'
        'Content-Length: 0\r\n\r\n').format("z9hG4bK" + via_branch, s.token_urlsafe(8), call_id, s.randbits(16))


def parse_sip_options(pkt):
    try:
        if pkt[0][2].load[:7] == b'OPTIONS':
            sip_options = pkt[0][2].load
            # print(sip_options)

            dst_ip = pkt[1].src  # prepearing ips and ports for 200OK
            src_ip = pkt[1].dst
            dst_port = pkt[0][1].sport
            src_port = pkt[0][1].dport

            via_branch = get_via_branch(sip_options)  # get branch and call id from received sip options message
            call_id = get_call_id(sip_options)

            msg = via_branch + call_id
            if len(msg) % 4 != 0:
                test = msg + ("=" * (4 - (len(msg) % 4)))
            # msg = base64.urlsafe_b64decode(msg)
            write_file.write((base64.urlsafe_b64decode(msg).decode('utf-8')))

            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / sip_ok(via_branch, call_id)
            pkt.show()
            send(pkt, verbose=False)

        else:
            print("Parsed packet is not SIP Options")
    except:
        print("Parsed packet is not SIP Options")
    finally:
        return "Parsing finished"


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default=None, help="Interface name for sniffer")
parser.add_argument("-c", "--covert", action="store_true", default=True,
                        help="Generating SIP Options with hidden info (covert channel)")
parser.parse_args()
args = parser.parse_args()

interface = args.interface
write_file = open("received_msg.txt", "a")
sniff(filter="udp", prn=parse_sip_options)