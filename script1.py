
from scapy.all import *

def PacketHandler (pkt) :

        if pkt.haslayer(Dot11):

                if pkt.type == 0:

                        if pkt.subtype == 4:
                                print("MGMT-Probe Request: Device MAC %s asking for SSID: %s" %(pkt.addr2, pkt.info))

                        elif pkt.subtype == 0:
                                print("MGMT-Association Request: Device MAC %s trying to SSID %s" %(pkt.addr2, pkt.info))

                        elif pkt.subtype == 2:
                                printf("MGMT-Reassociation Request: Device MAC %s trying to SSID %s" %(pkt.addr2, pkt.info))

                elif pkt.type == 1:

                        if pkt.subtype == 11:
                                print("CTRL-RTS: Device MAC %s is doing RTS" %(pkt.addr2))

sniff(iface="wlan0mon", prn = PacketHandler)
