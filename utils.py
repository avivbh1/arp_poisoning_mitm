import socket
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import uuid


def get_mac_address():  # weird
    # Gets the hostname of the local machine
    hostname = socket.gethostname()

    # Gets the MAC address using the hostname
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    mac_address = ":".join([mac[e:e + 2] for e in range(0, 12, 2)])

    return mac_address


def get_local_ip():
    try:
        # Create a socket to the default gateway and get the local IP address
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except Exception as e:
        return str(e)


def get_gateway_ip():
    try:
        # Create an ARP request packet to find the gateway's IP
        arp = ARP(pdst="0.0.0.0")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send the packet and receive a response
        result, _ = srp(packet, timeout=3, verbose=False)

        # Extract the IP address from the response
        for sent, received in result:
            return received.psrc

    except Exception as e:
        return None
