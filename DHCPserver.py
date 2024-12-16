from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff
import FetchNetwork


IP_INDEX = 0


DISCOVER = 1
OFFER = 2
SUBNET_MASK = "255.255.255.0"
IP_POOL = list()
BASE_IP = "10.0.0."

HOST_IP = FetchNetwork.GetIP()
HOST_MAC = FetchNetwork.GetMAC()

print(HOST_IP, HOST_MAC)

def main():
    sniff(filter="udp", prn=getDHCP, store=0)

def getDHCP(packet):
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return False
    
    ether = packet["Ethernet"]
    dhcp = packet["DHCP"]
    dst_mac = ether.src

    dhcp_messgae = dhcp.options[0]
    print(dhcp_messgae, DISCOVER)
    if(dhcp_messgae[1] == DISCOVER):
        dhcp_offer(dst_mac)

    return True


def dhcp_offer(dst_mac):
    global IP_INDEX

    if(IP_INDEX > 255): 
        return 

    print(dst_mac)
    print(str(IP_INDEX))
    ip_offer = BASE_IP + str(IP_INDEX)
    print(ip_offer)

    ethernet = Ether(dst=dst_mac)
    ip = IP(src=HOST_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)

    bootp = BOOTP (
        op=2,  # BOOT Reply
        yiaddr = ip_offer,  # Your (client) IP address
        siaddr=HOST_IP,  # Server IP address
        chaddr=bytes.fromhex(dst_mac.replace(":", "")),  # Client hardware address
    )


    dhcp = DHCP (
        options=[
            ("message-type", OFFER),  # DHCP Offer
            ("server_id", HOST_IP),  # DHCP Server Identifier
            ("lease_time", 86400),  # IP address lease time
            ("subnet_mask", SUBNET_MASK),  # Subnet mask
            ("end"),
        ]
    )

    dhcp_offer = ethernet / ip / udp / bootp / dhcp
    print(dhcp_offer.show())
    sendp(dhcp_offer, iface="Ethernet 2") 
    IP_INDEX += 1
    

if(__name__ == "__main__"):
    main()