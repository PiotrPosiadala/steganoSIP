from scapy.all import *
import argparse

'''
steganoDetector
Detecting if pcap file given 
in argument contains coverted 
information in SIP Options message
'''


def stegano_checker(sip):
    call_info_index = sip.find(b'Call-Info:') + 51
    call_info = sip[call_info_index:call_info_index+1]
    call_info = call_info.decode('UTF-8')
    if call_info == ".":
        stegano = True
    return stegano


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="Path to file to be checked")
parser.parse_args()
args = parser.parse_args()

file = args.file

pkts = sniff(offline=file)

for pkt in pkts:
    try:
        if pkt[0][2].load[:7] == b'OPTIONS':
            sip_options = pkt[0][2].load
            # print(sip_options)
            stegano = stegano_checker(sip_options)    
            
            if stegano:
                print("This pcap file contains coverted information")
            else:
                print("This pcap file does not contain coverted information")

    except:
        pass
