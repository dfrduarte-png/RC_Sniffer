from scapy.all import Ether, ARP, IP, ICMP, UDP, BOOTP, DHCP, sendp
import sys

def generate_test_traffic(interface):
    """Generates sample packets for ARP, ICMP, and DHCP to test the sniffer."""
    print(f"[INFO] Generating test traffic on {interface}...")

    try:
        # 1. ARP Request: "who has 192.168.0.254 says [your ip]"
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.0.254")
        sendp(arp_req, iface=interface, verbose=False)
        print("[OK] Sent ARP Request")

        # 2. ICMP Echo Request: A standard Ping
        icmp_req = Ether()/IP(dst="8.8.8.8")/ICMP()
        sendp(icmp_req, iface=interface, verbose=False)
        print("[OK] Sent ICMP Echo Request")

        # 3. DHCP Discover: Broadcast search for a DHCP server
        dhcp_dis = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr="00:11:22:33:44:55") /
                    DHCP(options=[("message-type", "discover"), "end"]))
        sendp(dhcp_dis, iface=interface, verbose=False)
        print("[OK] Sent DHCP Discover")

    except PermissionError:
        print("[ERROR] Sending packets requires root privileges. Please run with sudo.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python src/generator.py <interface>")
    else:
        generate_test_traffic(sys.argv[1])
