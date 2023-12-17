#bridge.py

import socket
import select
import argparse
import os
import sys
import time

# Timeout value in seconds (adjust as needed)
MAC_TO_PORT_TIMEOUT = 180  # 3 minutes

# Initialize a dictionary to store the timestamp of the last activity for each MAC address
mac_last_activity = {}


# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('lan_name', help='LAN name')
parser.add_argument('num_ports', type=int, help='Maximum number of stations')
args = parser.parse_args()

# Symbolic link files
ip_file_name = '{}_ip.txt'.format(args.lan_name)
port_file_name = '{}_port.txt'.format(args.lan_name)

if os.path.exists(ip_file_name) or os.path.exists(port_file_name):
    print("A bridge for LAN name {} already exists.".format(args.lan_name))
    sys.exit(1)  # Exit the program with a non-zero status code to indicate an error.

# Create a TCP socket
bridge_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the local IP address
local_ip = socket.gethostbyname(socket.gethostname())
# Bind the socket to a specific IP and port
bridge_socket.bind((local_ip, 0))
bridge_port = bridge_socket.getsockname()[1]

# Listen for incoming connections
bridge_socket.listen(5)

# Symbolic link files
with open(ip_file_name, "w") as f:
    f.write(local_ip)
with open(port_file_name, "w") as f:
    f.write(str(bridge_port))

# Initialize a dictionary to store port-to-MAC address mappings
mac_to_port = {}

# A list to keep track of established connections
established_connections = []

# Define the maximum number of ports
num_ports = args.num_ports

try:
    while True:
        # Use select to handle multiple events (connection setup request, data frames, and keyboard input)
        inputs = [bridge_socket] + established_connections + [sys.stdin]
        readable, _, _ = select.select(inputs, [], [])

        current_time = time.time()

        for sock in readable:
            if sock is bridge_socket:
                # Handle connection setup request
                if len(established_connections) < num_ports:
                    conn, addr = bridge_socket.accept()
                    established_connections.append(conn)
                    conn.send("accept".encode())
                    print("Accepted connection from {}".format(addr))
                else:
                    # If the maximum number of connections is reached, reject the connection
                    conn, _ = bridge_socket.accept()
                    conn.send("reject".encode())
                    conn.close()
                break
            elif sock is sys.stdin:
                # Handle keyboard input
                user_input = raw_input()
                if user_input:
                    # Extract the command and content from user input
                    command, content = user_input.split(" ", 1) if " " in user_input else (user_input, "")

                    if command == "show" and content == "sl":
                        # Print self-learning table (mac to port mapping)
                        print("Self-learning Table:")
                        for mac, port in mac_to_port.items():
                            print("MAC: {}, Port: {}".format(mac, port))
                    elif command == "quit":
                        # Close the bridge
                        print("Closing all connections. Exiting.")
                        for conn in established_connections:
                            conn.close()
                        bridge_socket.close()
                        sys.exit(0)
                    else:
                        print("Unknown command")
            else:
                # Handle data frame arrival
                try:
                    data = sock.recv(1024)
                    if not data:
                        # Connection closed
                        print("Connection {} closed".format(sock.getpeername()))
                        sock.close()
                        # Remove the entry from mac to port mapping
                        for mac, port in list(mac_to_port.items()):
                            if port == sock:
                                del mac_to_port[mac]
                                del mac_last_activity[mac]
                        established_connections.remove(sock)
                    else:
                        # Extract source and destination MAC addresses from the data frame
                        destination_mac = data[:17]
                        source_mac = data[17:34]

                        # Update timestamp for the source MAC address
                        mac_last_activity[source_mac] = current_time

                        if source_mac not in mac_to_port:
                            # If the source MAC address is not in the mapping, add it with the incoming port
                            mac_to_port[source_mac] = sock

                        if destination_mac in mac_to_port:
                            # If the destination MAC address is known, forward the frame to the corresponding port
                            destination_port = mac_to_port[destination_mac]
                            if destination_port != sock:
                                destination_port.send(data)       
                        else:
                            # Broadcast the data frame to all ports except the incoming one
                            for port in established_connections:
                                if port != sock:
                                    port.send(data)
                except:
                    continue
        # Check for inactive MAC addresses and remove them from the mapping
        for mac, last_activity_time in list(mac_last_activity.items()):
            if current_time - last_activity_time > MAC_TO_PORT_TIMEOUT:
                del mac_to_port[mac]
                del mac_last_activity[mac]
except KeyboardInterrupt:
    # Handle keyboard interrupt (Ctrl+C) to gracefully exit the loop
    print("Keyboard interrupt received. Closing all connections.")
    for conn in established_connections:
        conn.close()
    bridge_socket.close()
    sys.exit(0)