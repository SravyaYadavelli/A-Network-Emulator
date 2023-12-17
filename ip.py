# ip.py
import time

ARP_REQUEST = 0
ARP_RESPONSE = 1
PROT_TYPE_UDP = 0
PROT_TYPE_TCP = 1
PROT_TYPE_OSPF = 2

class Iface:
    def __init__(self, ifacename, ipaddr, macaddr, lanname):
        self.ifacename = ifacename
        self.ipaddr = ipaddr
        self.macaddr = macaddr
        self.lanname = lanname

class ITF2LINK:
    def __init__(self, ifacename, sockfd):
        self.ifacename = ifacename
        self.sockfd = sockfd

class Rtable:
    def __init__(self, destsubnet, nexthop, mask, ifacename):
        self.destsubnet = destsubnet
        self.nexthop = nexthop
        self.mask = mask
        self.ifacename = ifacename

class Arpc:
    def __init__(self, ipaddr, macaddr):
        self.ipaddr = ipaddr
        self.macaddr = macaddr
        self.last_activity = time.time()

class ARP_LIST:
    def __init__(self, arp_item, next):
        self.arp_item = arp_item
        self.next = next

class ARP_PKT:
    def __init__(self, op, srcip, srcmac, dstip, dstmac):
        self.op = op
        self.srcip = srcip
        self.srcmac = srcmac
        self.dstip = dstip
        self.dstmac = dstmac

class IP_PKT:
    def __init__(self, dstip, srcip, protocol, sequenceno, length, data):
        self.dstip = dstip
        self.srcip = srcip
        self.protocol = protocol
        self.sequenceno = sequenceno
        self.length = length
        self.data = data

class PENDING_QUEUE:
    def __init__(self, next_hop_ipaddr, src_iface, pending_pkt, next):
        self.next_hop_ipaddr = next_hop_ipaddr
        self.src_iface = src_iface
        self.pending_pkt = pending_pkt
        self.next = next

class OLD_PACKETS:
    def __init__(self, packet, length, counter, next):
        self.packet = packet
        self.length = length
        self.counter = counter
        self.next = next

# Additional global variables
MAXHOSTS = 32
MAXINTER = 32

host = [None] * MAXHOSTS
hostcnt = 0

iface_list = [None] * MAXINTER
lan_router = [None] * MAXINTER
link_socket = [None] * MAXINTER
intr_cnt = 0

rt_table = [None] * (MAXHOSTS * MAXINTER)
rt_cnt = 0

pending_queue = []
arp_cache = []
ROUTER = 0  # Initialize ROUTER to an appropriate value
