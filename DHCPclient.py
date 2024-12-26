from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, RandMAC
import FetchNetwork
import random

DISCOVER = 1
OFFER = 2
REQUEST = 3
ACK = 5
RELEASE = 7

HOST_IP = FetchNetwork.GetIP()
HOST_MAC = FetchNetwork.GetMAC()
HOST_MAC = HOST_MAC.replace("-",":")




current_xid = 0
taken_ip = []
server_ip = ""
fake_mac = str(RandMAC())

"""
message-type
client_id
requested_addr
server_id
hostname
client_FQDN
vendor_class_id
param_req_list
"""


def main():
    dhcp_discover()    
    sniff(filter="udp", stop_filter=getDHCP, store=0)
    curr_ip = taken_ip[0]
    print(taken_ip)
    dhcp_release(curr_ip[1], curr_ip[0])


def getDHCP(packet):

    global server_ip
    global taken_ip
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return False
    


    dhcp = packet["DHCP"]
    dst_mac = packet["Ethernet"].src
    dhcp_id = packet[BOOTP].xid

    if(dhcp_id != current_xid):
        return False

    dhcp_messgae = dhcp.options[0]
    
    if(dhcp_messgae[1] == OFFER):
        offered_ip = packet["BOOTP"].yiaddr
        server_ip = find_option("server_id", dhcp)[1]
        dhcp_request(offered_ip)
    
    if(dhcp_messgae[1] == ACK):
        ip = packet["BOOTP"].yiaddr
        taken_ip.append((fake_mac, ip))
        print("found ack")
        return True    


    return False


def dhcp_discover():

    global current_xid

    try:
        current_xid = random.randint(0, 0xFFFFFFFF)
        ethernet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") 
        ip = IP(src="0.0.0.0", dst="255.255.255.255")  # Source IP is 0.0.0.0, destination is broadcast
        udp = UDP(sport=68, dport=67)  # DHCP client port 68 to DHCP server port 67
        bootp = BOOTP(chaddr=bytes.fromhex(fake_mac.replace(":", "")), xid=current_xid, flags=0x8000)

        dhcp_discover = DHCP(
            options=[
                ("message-type", DISCOVER),  # Specify DHCP Discover
                ("param_req_list", [1, 3, 6, 15, 119, 252]),  # Parameters requested (subnet mask, router, DNS, etc.)
                ("end")
            ]
        )
    except Exception as e:
        print("failed to create a packet for discover")
        return

    dhcp_packet = ethernet / ip / udp / bootp / dhcp_discover
    sendp(dhcp_packet, iface=FetchNetwork.INTERFACE) 




def dhcp_request(offered_ip):

    try:
        ethernet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") 
        ip = IP(src="0.0.0.0", dst="255.255.255.255")  # Source IP is 0.0.0.0, destination is broadcast
        udp = UDP(sport=68, dport=67)  # DHCP client port 68 to DHCP server port 67
        bootp = BOOTP(chaddr=bytes.fromhex(fake_mac.replace(":", "")), xid=current_xid)
        dhcp_request = DHCP(
            options=[
                ("message-type", REQUEST),  # Specify DHCP Discover
                ("client_id", fake_mac),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("hostname", "daniel"),
                ("client_FQDN", "\x00\x01\x00\x00daniel"),
                ("venedor_class_id", "MSFT 5.0"),
                ("param_req_list", [1, 3, 6, 15, 119, 252]),  # Parameters requested (subnet mask, router, DNS, etc.)
                ("end")
            ]
        )
    except Exception as e:
        print("failed to create a packet for request")


    dhcp_packet = ethernet / ip / udp / bootp / dhcp_request
    sendp(dhcp_packet, iface=FetchNetwork.INTERFACE) 




def dhcp_release(leased_ip, client_mac):
    try:
        ether = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") 
        ip =  IP(src=leased_ip, dst=server_ip) 
        udp =  UDP(sport=68, dport=67) 

        bootp = BOOTP(
                chaddr=bytes.fromhex(client_mac.replace(":", "")),
                ciaddr=leased_ip  # Client's IP address
            ) 

        dhcp_release = DHCP(
                options=[
                    ("message-type", "release"),  # DHCP Release message type
                    ("server_id", server_ip),    # DHCP Server Identifier
                    ("client_id", client_mac),  # Client Identifier
                    ("end")                     # End of options
                ]
            )
    except Exception as e:
        print("failed to create a packet for release")

    dhcp_packet = ether / ip/ udp / bootp / dhcp_release
    sendp(dhcp_packet, iface=FetchNetwork.INTERFACE) 


def find_option(option, dhcp):
        for opt in dhcp.options:
            if (opt[0] == option):  # Check for Server Identifier option 
                return opt

if(__name__ == "__main__"):
    main()