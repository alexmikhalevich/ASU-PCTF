import argparse
from scapy.all import *


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='iface')
    args = parser.parse_args()
    return args

def sniffer(iface):
    sniff(iface=iface, prn=analyze_packet, count=0)

def analyze_packet(pkt):
    if TCP in pkt:
        body = str(pkt[TCP].payload)
        for i in malicious:
            if i in body:
                ip = IP(src=pkt[IP].dst,dst=pkt[IP].src) 
                tcp = TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags='R',seq=pkt.ack)
                msg = ip/tcp
                send(msg)  

if __name__ == "__main__":

    args = get_arguments()
    if args.iface == None:
         print("You have to add an interface like : ./script --interface <interface>")
    else:
        with open('payloads.txt') as f:
            malicious = f.read().splitlines()
            
        sniffer(args.iface)

