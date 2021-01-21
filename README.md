# manInTheMiddle-MITM-Attack
1. networkScan
2. arpPoisoning  
3. packetSniff  
4. DNS_Attack.

## Dependencies
```
apt install python3-scapy
```

install the scapy http library from the terminal:
```
pip install scapy-http
```

## Installation

```
git clone https://github.com/Angellito10/manInTheMiddle-MITM-Attack.git
cd manInTheMiddle-MITM-Attack-master
```
## Usage

```
sudo python scanner.py 
sudo python3 scanner.py 
sudo python fileName.py
```

**All steps Needs "root" privileges.**
## 1- networkScan 

In order to become **Man-in-the-Middle (MitM**). the attacker needs to inserts himself between two network nodes, to achieve this the attacker needs to use information-gathering tools. the **scanner.py** script will ask the attacker to enter the **network_ID,** then the script will perform arpPing to collect the information about the devices connected to the network, as shown in the image below.

```sudo python scanner.py ```

![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/master/img/scanner.png)

Now the attacker has a list of IPs with MAC addresses for each device connected to the network. 

## 2- arpPoisoning 

### arp poisoning using kali tools: 
- to spoof arp in getaway: first sent arp request to the gateway tell it I'm at that specific IP.
- to spoof arp in target: send arp respond to the target tell it I'm the getaway.
- using kali **aprspoof** target: arpspoof -i interface -t ipTarget ipGetaway: **arpspoof -i eth0 -t 10.10.1.20 10.10.1.1**.
- using kali aprspoof getway: **arpspoof -i eth0 -t getwayIP myIP**.

### arp poisoning usig arp_spoof.py script: 

```sudo python arp_spoof.py ```

The attacker needs to specify the target IP and the default gateway IP, the script uses SCAPY will create entries on the target's ARP Table, the script will redirect all the traffic flow between the target and the default gateway through the attacker machine.

It's mandatory to enable port forwarding in the attacker machine for allows the traffic that comes from the victim machine to go to the default gateway. 

- To allow the computer to do port forwarding in **linux:** `` echo 1> /proc/sys/net/ipv4/ip_forward``
- To allow the computer to do port forwarding in **mac:** ``sysctl -w net.inet.ip.forwarding=1`` 

![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/master/img/arp_sniff_1.png)

- Keep the script in **terminal 1 running** because we need the script to keep sending the arp spoofing packets 

## 3- packetSniff
A packet sniffer — also known as a packet analyzer, protocol analyzer, or network analyzer — is a piece of hardware or software used to monitor network traffic. Sniffers work by examining streams of data packets that flow between computers on a network as well as between networked computers and the larger Internet.

Before you run this script ```sudo python packetSnifferPY2.py``` you should open the script in any text editor. then go to the last line and change the name of the interface **sniff("en0")**, you need to put your computer interface name. 

- To get your computer interface name in **linux / mac** open terminal then run **ifconfig** now you can put in **sniff("yourInterFaceName")**
- To get your computer interface name in **Windows** open CMD then run **ipconfig** now you can put in **sniff("yourInterFaceName")**

After All, steps are successfully done,  you are ready to go: run the script ```sudo python packetSnifferPY2.py```
In the script python packages: - import scapy.all as scapy - from scapy.layers import HTTP will do the packet capturing then return the result, of the specific field you specify, in the script **packetSnifferPY2.py** I specified only to return the HTTP user name and password. 

![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/master/img/Screenshot%202021-01-21%20at%202.34.27%20PM.png)

Now if you run this against the VM machine open the VM machine the try to login to any HTTP website, you will be able to capture the user name and password only.

![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/main/sniff_3.png)

Furthermore, you can capture all the links in the victim machine In the script I used httpyear package to filter that, then return all the links also the user name and password. as shown in the image below.

![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/master/img/snif_url.png)

## 4. DNS_Attack.

using DNS poisoning, you ultimately route users to the wrong website. this is one of those complex scripts that can let us do that easily.
To run the script you need to linux machine: 

- To perform this attack we can create a queue in the machine we are doing the attack on.
- The packet will flow through our machine and we can store the packet on the queue we have created.
- After that, we need to access this queue from the python program to modify it, as we want.
- Then we send the modified packet the target will receive only the packet.
- So the same way goes for the response packet.

> Execute the attack: 
1- We need to redirect the packet recived to the queue using: **[iptables]** which can modifying routing rules.
> ```iptables -I FORWARD -j NFQUEUE --queue-num [anyNumber]```:
-> iptables [this allows us to wrap the packet to queue]
-> -I [to specify the packet chaine wather it (FORWARD, PACKWARD)]
-> -j [to select the queue]
-> NFQUEUE [Network filter queue]
-> queue-num [ the number in the queue packe will be store]
2- Now we need to access the queue: by using python mudole[ netfilterqueue ]


- ```apt-get install build-essential python-dev libnetfilter-queue-dev```
- ``pip install netfilterqueue``
- ``apt-get install libnetfilter-queue-dev``
- then  ran this to install netfilterqueue python 3 version:
- ``pip3 install NFQP3``

you can open the script then read the instruction on it.

```sudo python DNS_attack.py ```


![GitHub Logo](https://github.com/Angellito10/manInTheMiddle-MITM-Attack/blob/master/img/dns.png)

Inconclusion, you can modify the traffic but in this repository, I used python only to do the demo about those types of attacks, you can go through that by yourself .


