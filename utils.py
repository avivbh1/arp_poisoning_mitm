import socket
import uuid


def get_local_mac_address():
    """
    Gets local machine's MAC address
    :return: mac address
    """
    mac = uuid.UUID(int=(uuid.getnode() - 1)).hex[-12:]
    return ":".join([mac[e:e + 2] for e in range(0, 12, 2)])


def get_local_ip():
    """
    Gets local machine's IP address
    :return: ip address
    """
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except Exception as e:
        return str(e)


# def get_default_gateway_mac(ip_address):
#     """
#     Gets the mac address of the default gateway (router) of the network you're connected to
#     :param ip_address:
#     :return:
#     """
#     try:
#         output = subprocess.check_output(["arp", "-a", ip_address])
#         output = output.decode("utf-8")
#         mac_address = output.split()[11]
#         return mac_address
#     except Exception as e:
#         print("Error:", e)
#         return None
#
#
