from firewall import *

import argparse
from scapy.all import *

import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='iface')
    args = parser.parse_args()
    return args

def sniffer(iface):
    sniff(iface=iface, prn=analyze_packet, count=0)

def analyze_packet(pkt):
    # if malicious
        # get source port
        # add_rule("source port")
    pass

args = get_arguments()
sniffer(args.iface)

