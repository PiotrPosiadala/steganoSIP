from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default=None, help="Interface name for sniffer")
parser.parse_args()
args = parser.parse_args()

interface = args.interface


# pkts = sniff(filter="udp", iface=interface, prn=lambda x: x.show())



