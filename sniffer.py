import scapy.all as scapy
from scapy.layers import http
import argparse

def option_inputs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="interface   usage : -i eth0")
    pars = parser.parse_args()
    return pars

def packet_capture(interface):
    scapy.sniff(iface=interface, store=False, prn=sniff_response)


def sniff_response(sniff_packet):
     if sniff_packet.haslayer(http.HTTPRequest):
         print("1-",sniff_packet[http.HTTPRequest].Host,sniff_packet[http.HTTPRequest])
         if sniff_packet.haslayer(scapy.Raw):
             print("2-",sniff_packet[scapy.Raw].load)
user_inputs = option_inputs()
packet_capture(user_inputs.interface)
