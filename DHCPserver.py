from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, RandMAC
import FetchNetwork
IP_INDEX = 0

#Remember to add broadcast flag to BOOTP

BANNED_MACS = ["fc:8f:7d:0a:b4:53"]
DISCOVER = 1
OFFER = 2
REQUEST = 3
SUBNET_MASK = "255.255.255.0"
IP_POOL = list()
BASE_IP = "10.0.0."

offers = dict()

HOST_IP = FetchNetwork.GetIP()
HOST_MAC = FetchNetwork.GetMAC()
HOST_MAC = HOST_MAC.replace("-",":")

print(HOST_IP, HOST_MAC)

def main():
    sniff(filter="udp", prn=getDHCP, store=0)

def getDHCP(packet):

    global offers
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return
    if(packet["Ethernet"].src in BANNED_MACS):
        return
    
    dhcp = packet["DHCP"]
    dst_mac = packet["Ethernet"].src
    dhcp_id = packet[BOOTP].xid

    dhcp_messgae = dhcp.options[0]
    #print(dhcp_messgae, DISCOVER)
    if(dhcp_messgae[1] == DISCOVER):
        offers[dst_mac] = dhcp_id
        dhcp_offer(dst_mac)
    elif(dhcp_messgae[1] == REQUEST):
        dhcp_ack(dst_mac)


def dhcp_offer(dst_mac):


    if(IP_INDEX > 255): 
        return 

    print(dst_mac)
    print(str(IP_INDEX))
    ip_offer = BASE_IP + str(IP_INDEX)
    print(ip_offer)

    ethernet = Ether(src=HOST_MAC, dst=dst_mac)
    ip = IP(src=HOST_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)

    bootp = BOOTP (
        op=2,  # BOOT Reply
        yiaddr = ip_offer,  # Your (client) IP address
        siaddr=HOST_IP,  # Server IP address
        xid = offers[dst_mac], 
        chaddr=bytes.fromhex(dst_mac.replace(":", "")),  # Client hardware address
    )


    dhcp = DHCP (
        options=[
            ("message-type", OFFER),  # DHCP Offer
            ("server_id", HOST_IP),  # DHCP Server Identifier
            ("lease_time", 86400),  # IP address lease time
            ("subnet_mask", SUBNET_MASK),  # Subnet mask
            ("router", HOST_IP),
            ("name_server", HOST_IP),  # Option 6
            ("domain", "Home"),  # Option 15
            ("end"),
        ]
    )

    dhcp_offer = ethernet / ip / udp / bootp / dhcp
    #print(dhcp_offer.show())
    print(offers)
    sendp(dhcp_offer, iface=FetchNetwork.INTERFACE) 


def dhcp_ack(dst_mac):
    global IP_INDEX
    ip_offer = BASE_IP + str(IP_INDEX)
    ethernet = Ether(src=HOST_MAC, dst=dst_mac)
    ip = IP(src=HOST_IP, dst=ip_offer)
    udp = UDP(sport=67, dport=68)

    bootp = BOOTP (
        op=2,  # BOOT Reply
        yiaddr = ip_offer,  # Your (client) IP address
        siaddr=HOST_IP,  # Server IP address
        xid = offers[dst_mac],
        chaddr=bytes.fromhex(dst_mac.replace(":", "")),  # Client hardware address
    )

    dhcp = DHCP(options=[
        ("message-type", "ack"),
        ("server_id", HOST_IP),  # Replace with your server IP
        ("subnet_mask", SUBNET_MASK),
        ("router", HOST_IP),
        ("lease_time", 86400),
        ("name_server", HOST_IP),  # Option 6
        ("domain", "Home"),  # Option 15
        ("end")
    ])

    # Combine all layers into a single packet
    dhcp_ack_packet = ethernet / ip / udp / bootp / dhcp

    # Send the packet
    sendp(dhcp_ack_packet, iface=FetchNetwork.INTERFACE)
    del offers[dst_mac]
    IP_INDEX += 1
    






    

if(__name__ == "__main__"):
    main()