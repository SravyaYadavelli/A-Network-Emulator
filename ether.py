# ether.py

PEER_CLOSED = 2
TYPE_IP_PKT = 1
TYPE_ARP_PKT = 0

class EtherPkt:
    def __init__(self, dst, src, type, size, dat):
        self.dst = dst
        self.src = src
        self.type = type
        self.size = size
        self.dat = dat
