from scapy.all import *
import argparse
import secrets as s

def get_call_id(sip):
    call_id_index = sip.find(b'Call-I') + 9
    call_id_end_index = sip.find(b'@', call_id_index)
    call_id = sip[call_id_index:call_id_end_index]
    return call_id

def get_via_branch(sip):
    branch_index = sip.find(b'branch=') + 7
    branch_end_index = sip.find(b'\r', branch_index)
    branch = sip[branch_index:branch_end_index]
    return branch

def sip_ok(via_branch, call_id):
    print("sip_ok_generating")
    return(
        'SIP/2.0 200 OK\r\n'
        'Via: SIP/2.0/UDP sbcwaw1@pw.edu.pl;branch={0}\r\n'
        'From: <sip:terminal01121605@pw.edu.pl>\r\n'
        'To: \"presenceserverwaw1\"<sip:presenceserverwaw1@pw.edu.pl>\r\n'
        'Call-ID: {2}@pw.edu.pl\r\n'
        'CSeq: {3} OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        'Call-Info: I am avaiable\r\n'
        'Organization: Warsaw University of Technology, Faculty of Electronics and Information Technology \r\n'
        'Content-Length: 0\r\n\r\n').format(via_branch, s.token_urlsafe(8), call_id, s.randbits(16))

def generate_sip_ok(pkt):
    sip_options = pkt[0][2].load
    print(sip_options)
    
    dst_ip = pkt[1].src                         # prepearing ips and ports for 200OK
    scr_ip = pkt[1].dst
    dst_port = pkt[0][1].sport
    src_port = pkt[0][1].dport

    via_branch = get_via_branch(sip_options)    # get branch and call id from received sip options message
    call_id = get_call_id(sip_options)
    
    #TODO new pkt is not being generated correctly
    pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/sip_ok(via_branch, call_id)
    send(pkt)

def parse_sip_options(packet):
    try:
        if packet[0][2].load[:7] == b'OPTIONS':
            generate_sip_ok(packet)                              #if received packet is sip options then generate and send sip ok status
        else: 
            print("Parsed packet is not SIP Options")
    except:
        print("Parsed packet is not SIP Options")

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default=None, help="Interface name for sniffer")
parser.parse_args()
args = parser.parse_args()

interface = args.interface

pkts = sniff(filter="udp", prn=parse_sip_options)







