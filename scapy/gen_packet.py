from scapy.all import *

f = open("test.jpg", "rb")
jpg = f.read()
f.close()

start = 0
end = len(jpg) / 40 + 1

for i in range(1, 41):
    raw = jpg[start:end]
    packet = (IP(dst="192.168.1.1")/ICMP(id=0x1234, seq=(i-1))/raw)

    sr1(packet)

    start = end
    end = start + len(jpg) / 40 + 1
