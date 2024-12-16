import socket
import uuid
import psutil
import socket 

INTERFACE = "Ethernet 2"






def GetIP():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == INTERFACE:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"Interface: {interface}, IP Address: {addr.address}")
                    return addr.address


def GetMAC():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == INTERFACE:
            for addr in addrs:
                # Check if it's a MAC address (AF_LINK)
                if addr.family == psutil.AF_LINK:
                    print(f"Interface: {interface}, MAC Address: {addr.address}")
                    return addr.address


        




def main():
    #HOST_MAC = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
    #mac = uuid.getnode()
    return


if(__name__ == '__main__'):
    main()