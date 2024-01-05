
from scapy.all import *
from threading import Thread
import os
import time

interface = "wlan0mon"

def change_channel():
	chan = 1
	while True:
		os.system(f"iwconfig {interface} channel {chan}")
		chan = chan +1
		if chan > 11:
			chan = 1
		print("On channel %s" %(chan))
		print("--------------")
		time.sleep(1)

def PacketHandler (pkt) :

	if pkt.haslayer(Dot11):

# Go for the mgmt and ctrl frames analysis

		if pkt.type == 0:

			if pkt.subtype == 4:
				print("MGMT-Probe Request: Device MAC %s asking for SSID %s" %(pkt.addr2, pkt.info))

			elif pkt.subtype == 0: 
				print("MGMT-Association Request: Device MAC %s trying to SSID %s" %(pkt.addr2, pkt.info))

			elif pkt.subtype == 2:
				print("MGMT-Reassociation Request: Device MAC %s trying to SSID %s" %(pkt.addr2, pkt.info))

		elif pkt.type == 1:

			if pkt.subtype == 11:
				print("CTRL-RTS: Device MAC %s is doing RTS for SSID %s" %(pkt.addr2, pkt.info)) 

		elif pkt.type == 2:
	
			

# Change channel every sec
#channel_changer = Thread(target=change_channel)
#channel_changer.daemon = True
#channel_changer.start()

# Start sniffing
sniff(iface="wlan0mon", prn = PacketHandler)

