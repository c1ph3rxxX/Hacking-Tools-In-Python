#!usr/bin/env python
#original mac- 00:0c:29:da:52:66

import subprocess
import optparse
import re

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-i","--interface",dest="interface",help="interface to change mac address")
	parser.add_option("-m","--mac",dest="new_mac",help="new mac address")
	(options,arguments)=parser.parse_args()
	if not options.interface:
		parser.error("[-] Please specify an interface, use --help for more info")
	elif not options.new_mac:
		parser.error("[-] Please specify new mac address, use --help for more info")
	return options


def change_mac(interface, new_mac):
	subprocess.call(["ifconfig", interface, "down"])
	subprocess.call(["ifconfig", interface, "hw","ether",new_mac])
	subprocess.call(["ifconfig", interface, "up"])
	print("[+] changing MAC address to "+ new_mac)
	
	
def current_mac(interface):
	ifconfig_result = subprocess.check_output(["ifconfig", interface])
	#mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result) // get error in python3
	mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result)) #work with both py2/py3
	if mac_search_result:
		return mac_search_result.group(0)
	else:
		print("[-] could not read mac address")
		



options = get_arguments()
current_mac1 = current_mac(options.interface)
print("[+] current mac - " + str(current_mac1))	

change_mac(options.interface, options.new_mac)
current_mac2 = current_mac(options.interface)

if current_mac2 == options.new_mac:
	print("[+] MAC address successfully changed to "+ options.new_mac)
else:
	print("[-] MAC address did not get changed to "+ options.new_mac)




