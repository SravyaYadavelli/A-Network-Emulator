# station.py

import socket
import sys
import time
import select
import argparse
import struct
import pickle
import time
from ipaddress import *

# Load data from ifaces.a, rtable.a, and hosts files
from ip import *
from ether import *

# Timeout value in seconds (adjust as needed)
ARP_CACHE_TIMEOUT = 180  # 3 minutes

# Create an ARP cache to store IP-to-MAC address mappings
arp_cache = []

# Create a pending queue to store IP packets waiting for ARP resolution
pending_queue = []

def update_arp_entry_timestamp(ip_addr):
    for entry in arp_cache:
        if entry.ipaddr == ip_addr:
            entry.last_activity = time.time()
            break

# Function to handle ARP requests
def handle_arp_request(arp_pkt, iface):
    # Check if the ARP request is for our IP address
    if arp_pkt.dstip == iface.ipaddr:
        # Create an ARP reply packet
        arp_reply = pickle.dumps(ARP_PKT(ARP_RESPONSE, iface.ipaddr, iface.macaddr, arp_pkt.srcip, arp_pkt.srcmac))
        # Send the ARP reply
        send_frame(EtherPkt(arp_pkt.srcmac, iface.macaddr, TYPE_ARP_PKT, 0, arp_reply), iface)
    else:
        pass
    n=0
    for entry in arp_cache:
        if entry.ipaddr == arp_pkt.srcip:
            n=1
            break
    if n==0:
        # Add the ARP entry to the cache
        arp_cache.append(Arpc(arp_pkt.srcip, arp_pkt.srcmac))
    # Update the timestamp for the ARP entry
    update_arp_entry_timestamp(arp_pkt.srcip)

# Function to send an IP packet
def send_ip_packet(dstip, srcip, data, src_iface, next_hop_ip):
    # Check if we have the MAC address for the next hop IP in the ARP cache
    next_hop_mac = None
    if next_hop_ip=="0.0.0.0":
        next_hop_ip=dstip
    for entry in arp_cache:
        if entry.ipaddr == next_hop_ip:
            next_hop_mac = entry.macaddr
            # Update the timestamp for the ARP entry
            update_arp_entry_timestamp(next_hop_ip)
            break
    ip_packet = pickle.dumps(IP_PKT(dstip, srcip, PROT_TYPE_UDP, 0, len(data), data))        
    if next_hop_mac is not None:
        # Create an Ethernet frame and send the packet
        ether_frame = EtherPkt(next_hop_mac, src_iface.macaddr, TYPE_IP_PKT, len(ip_packet), ip_packet)
        send_frame(ether_frame, src_iface)
    else:
        # If we don't have the MAC address, send an ARP request
        arp_request = pickle.dumps(ARP_PKT(ARP_REQUEST, src_iface.ipaddr, src_iface.macaddr, next_hop_ip, "00:00:00:00:00:00"))
        send_frame(EtherPkt("ff:ff:ff:ff:ff:ff", src_iface.macaddr, TYPE_ARP_PKT, 0, arp_request), src_iface)
        # Store the IP packet in the pending queue
        pending_queue.append(PENDING_QUEUE(next_hop_ip, src_iface, ip_packet, None))
        lastedit=time.time()

def send_frame(eth_frame, iface):
    # Create the Ethernet frame by concatenating the destination MAC address, source MAC address, type, and data
    frame_data = (eth_frame.dst + eth_frame.src + struct.pack('!H', eth_frame.type) + struct.pack('!H', eth_frame.size) + bytes(eth_frame.dat))
    # Send the frame over the specified socket
    try:
        link_socket = link_sockets[iface.ifacename]
        link_socket.sendall(frame_data)
    except KeyError:
        # print("Interface '{}' isn't connected to LAN, source and destination aren't connected".format(iface.ifacename))
        pass
    except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
        print("Error sending frame: {}".format(e))


# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-no', action='store_true', dest='station', default=False, help='Specifies that this is a station instead of a router.')
parser.add_argument('ifaces_file', help='Path to the ifaces file (e.g., ifaces.iface_name)')
parser.add_argument('rtable_file', help='Path to the rtable file (e.g., rtables.rtable_name)')
parser.add_argument('hosts_file', help='Path to the hosts file (e.g., hosts)')
args = parser.parse_args()

router = not args.station  # If -no is specified, it's a station; otherwise, it's a router

# Load host mapping from hosts file
host_mapping = {}
with open(args.hosts_file) as hosts_file:
    for line in hosts_file:
        name, ip = line.split()
        host_mapping[name] = ip

# Load interface information from ifaces.a
ifaces = {}
with open(args.ifaces_file) as ifaces_file:
    for line in ifaces_file:
        parts = line.split()
        name, ip, mask, mac, lanname = parts
        ifaces[name] = Iface(name,ip,mac,lanname)

# Load routing table from rtable.a
routing_table = []
with open(args.rtable_file) as rtable_file:
    for line in rtable_file:
        destsubnet, nexthop, mask, ifacename = line.split()
        routing_table.append(Rtable(destsubnet, nexthop, mask, ifacename))

link_sockets={}
link_socket=None

# Initialize link_sockets dynamically based on ifaces file
for iface_name, iface in ifaces.items():
    # Extract LAN name from the iface entry
    lan_name = iface.lanname

    # Read LAN IP and port information from symbolic files
    lan_ip = None
    lan_port = None
    try_count = 5
    retry_interval = 5
    for i in range(try_count):
        try:
            with open('{}_ip.txt'.format(lan_name)) as lan_ip_file:
                lan_ip = lan_ip_file.read()
            with open('{}_port.txt'.format(lan_name)) as lan_port_file:
                lan_port = int(lan_port_file.read())
            if lan_ip and lan_port:
                link_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                link_socket.setblocking(0)
                try:
                    link_socket.connect((lan_ip, lan_port))
                    link_sockets[iface_name] = link_socket 
                    # Non-blocking socket
                    link_socket.setblocking(0)
                    break
                except:
                    link_sockets[iface_name] = link_socket 
                    # Non-blocking socket
                    link_socket.setblocking(0)
                    break
            else:
                print("Missing IP or port information for LAN {}".format(lan_name))
        except IOError as e:
            print("failed in {} iteration".format(i+1))
            if i == try_count - 1:
                print("Connection to the bridge failed.")
                sys.exit(1)
            time.sleep(retry_interval)

# Wait for an "accept" or "reject" response from the bridges
readable, _, _ = select.select(list(link_sockets.values()), [], [], 2)

# Iterate over the sockets and check for responses
for link_socket in list(link_sockets.values()):
    for i in range(try_count):
        try:
            response = link_socket.recv(1024).decode()
            if response == "reject":
                print("Connection to {} was rejected.".format(link_socket.getpeername()))
                sys.exit(1)
            elif response == "accept":
                print("Connection to {} was accepted.".format(link_socket.getpeername()))
                break
            else:
                if i == try_count - 1:
                    print("Connection to {} was rejected.".format(link_socket.getpeername()))
                    sys.exit(1)
                time.sleep(retry_interval)
        except socket.error as e:
            if e.errno == 11:
                # Resource temporarily unavailable (non-blocking)
                pass
            else:
                # Handle other socket errors
                print("Error receiving data: {}".format(e))

lastedit= time.time()

# Implement your station functionality (sending, receiving, and handling control messages) here
try:
    # Create a dictionary to map sockets to interface names
    socket_to_iface = {socket: iface_name for iface_name, socket in link_sockets.items()}
    # Main loop for station
    while True:
        readable, _, _ = select.select(list(link_sockets.values()) + [sys.stdin], [], [], 0)
        for input_source in readable:
            if input_source == sys.stdin:
                # Check if there's user input to send a message
                user_input = raw_input()
                if user_input:
                    # Extract the destination station name from user input
                    comm, content = user_input.split(" ", 1) if " " in user_input else (user_input, "")
                    if comm == "send" and not router:
                        dest_station_name, message = content.split(" ",1)
                        if dest_station_name in host_mapping:
                            dest_ip = host_mapping[dest_station_name]
                            # Search the routing table for the next hop and interface name based on the destination IP
                            next_hop = None
                            output_iface_name = None
                            for entry in routing_table:
                                dest_subnet = IPv4Network(unicode(entry.destsubnet) + '/' + unicode(entry.mask), strict=False)
                                if IPv4Address(unicode(dest_ip)) in dest_subnet:
                                    next_hop = entry.nexthop
                                    output_iface_name = entry.ifacename
                                    break
                            # If no specific route found, use the default route (0.0.0.0)
                            if not next_hop:
                                for entry in routing_table:
                                    if entry.destsubnet == "0.0.0.0":
                                        next_hop = entry.nexthop
                                        output_iface_name = entry.ifacename
                                        break
                            src_iface = ifaces[output_iface_name]
                            if next_hop and output_iface_name:
                                send_ip_packet(dest_ip, src_iface.ipaddr, message, src_iface, next_hop)
                        else:
                            print("No host with name {}".format(dest_station_name))
                    elif comm == "show":
                        if content == "arp":
                            # Print ARP table
                            print("ARP Cache Table:")
                            for entry in arp_cache:
                                print("IP: {}, MAC: {}".format(entry.ipaddr, entry.macaddr))
                        elif content == "pq":
                            # Print pending queue
                            print("Pending Queue:")
                            for pending in pending_queue:
                                ip_packet = pickle.loads(pending.pending_pkt)
                                print("Pending IP Packet - Destination IP: {}, Source IP: {}, Protocol Type: {}, Data Length: {}, Data: {}".format(
                                    ip_packet.dstip,
                                    ip_packet.srcip,
                                    ip_packet.protocol,
                                    ip_packet.length,
                                    repr(ip_packet.data)
                                ))
                        elif content == "host":
                            # Print IP/Name mapping table
                            print("IP/Name Mapping Table:")
                            for key, value in host_mapping.items():
                                print("Name: {}, IP: {}".format(key, value))
                        elif content == "iface":
                            # Print interface information
                            print("Interface Information:")
                            for iface_name, iface in ifaces.items():
                                print("Interface Name: {}, IP: {}, MAC: {}, LAN Name: {}".format(iface_name, iface.ipaddr, iface.macaddr, iface.lanname))
                        elif content == "rtable":
                            # Print routing table
                            print("Routing Table:")
                            for entry in routing_table:
                                print("Destination Subnet: {}, Next Hop: {}, Mask: {}, Interface Name: {}".format(entry.destsubnet, entry.nexthop, entry.mask, entry.ifacename))
                        else:
                            print("unknown argument")
                    elif comm == "quit":
                        # Close the sockets and close the station
                        print("Closing all connections. Exiting.")
                        for link_socket in list(link_sockets.values()):
                            link_socket.close()
                        sys.exit(0)
                    else:
                        print("unknown command")
            else:
                try:
                    data = input_source.recv(1024)
                    input_iface_name = socket_to_iface[input_source]
                    if not data:
                        # Connection closed
                        ls = link_sockets[input_iface_name]
                        print("Connection to {} closed.".format(ls.getpeername()))
                        del link_sockets[input_iface_name]
                        ls.close()
                        if not link_sockets:
                            print("disconnected from all the lANs")
                            print("Closing all connections.")
                            for link_socket in list(link_sockets.values()):
                                link_socket.close()
                            sys.exit(0)
                    else:
                        # Parse the received Ethernet frame
                        frame = EtherPkt(data[0:17],data[17:34],struct.unpack('!H', data[34:36])[0],struct.unpack('!H', data[36:38])[0],data[38:],)
                        # Handle different frame types
                        if frame.type == TYPE_IP_PKT:
                            # Handle IP packet
                            ip_data = frame.dat
                            ip_packet = pickle.loads(ip_data)
                            # Check if the packet is for this station
                            if ip_packet.dstip == ifaces[input_iface_name].ipaddr:
                                name = None
                                for key,value in host_mapping.items():
                                    if value == ip_packet.srcip:
                                        name = key
                                print("Received IP message from {}: {}".format(name,ip_packet.data))
                            else:
                                if router:
                                    # Forward the packet based on routing table
                                    # Search the routing table for the next hop and interface name based on the destination IP
                                    next_hop = None
                                    out_iface = None
                                    for entry in routing_table:
                                        dest_subnet = IPv4Network(unicode(entry.destsubnet) + '/' + unicode(entry.mask), strict=False)
                                        if IPv4Address(unicode(ip_packet.dstip)) in dest_subnet:
                                            next_hop = entry.nexthop
                                            out_iface = entry.ifacename
                                            break
                                    # If no specific route is found, use the default route (0.0.0.0)
                                    if not next_hop:
                                        for entry in routing_table:
                                            if entry.destsubnet == "0.0.0.0":
                                                next_hop = entry.nexthop
                                                out_iface = entry.ifacename
                                                break
                                    if next_hop is not None and out_iface is not None:
                                        send_ip_packet(ip_packet.dstip, ip_packet.srcip, ip_packet.data, ifaces[out_iface], next_hop)
                                else:
                                    pass
                        elif frame.type == TYPE_ARP_PKT:
                            # Handle ARP packet
                            arp_data = frame.dat
                            arp_packet = pickle.loads(arp_data)
                            if arp_packet.op == ARP_REQUEST:
                                # Handle ARP request
                                handle_arp_request(arp_packet, ifaces[input_iface_name])
                            elif arp_packet.op == ARP_RESPONSE:
                                # Handle ARP reply
                                n=0
                                for entry in arp_cache:
                                    if entry.ipaddr == arp_packet.srcip:
                                        n=1
                                        break
                                if n==0:
                                    # Add the ARP entry to the cache
                                    arp_cache.append(Arpc(arp_packet.srcip, arp_packet.srcmac))
                                    # Update the timestamp for the ARP entry
                                    update_arp_entry_timestamp(arp_packet.srcip)
                                # Check the pending queue for IP packets
                                items_to_remove = []
                                for pending in pending_queue:
                                    if pending.next_hop_ipaddr == arp_packet.srcip:
                                        # Create an Ethernet frame and send the packet
                                        ether_frame = EtherPkt(arp_packet.srcmac, pending.src_iface.macaddr, TYPE_IP_PKT, len(pending.pending_pkt), pending.pending_pkt)
                                        send_frame(ether_frame, pending.src_iface)
                                        items_to_remove.append(pending)
                                for item in items_to_remove:
                                    pending_queue.remove(item)
                            else:
                                print("ARP Packet Type Issue")
                        else:
                            pass
                except socket.error as e:
                    if e.errno == 11:
                        # Resource temporarily unavailable (non-blocking)
                        pass
                    else:
                        # Handle other socket errors
                        print("Error receiving data: {}".format(e))    
        if time.time()-lastedit>5:
            for pending in pending_queue:
                arp_request = pickle.dumps(ARP_PKT(ARP_REQUEST, pending.src_iface.ipaddr, pending.src_iface.macaddr, pending.next_hop_ipaddr, "00:00:00:00:00:00"))
                send_frame(EtherPkt("ff:ff:ff:ff:ff:ff", pending.src_iface.macaddr, TYPE_ARP_PKT, 0, arp_request), pending.src_iface)
                lastedit=time.time()
        for entry in arp_cache:
            # Check for inactive ARP entries and remove them from the cache
            if time.time() - entry.last_activity > ARP_CACHE_TIMEOUT:
                arp_cache.remove(entry)
except KeyboardInterrupt:
    # Handle keyboard interrupt (Ctrl+C) to gracefully exit the loop
    print("Keyboard interrupt received. Closing all connections.")
    for link_socket in list(link_sockets.values()):
        link_socket.close()
    sys.exit(0)
