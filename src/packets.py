from datetime import datetime
from scapy.all import PacketList, IP, TCP

def print_packets(packets: PacketList):
    i = 1
    for p in packets:
        print(f"--------------- Packet {i} ---------------")
        print(f"Arrival Time:\t{datetime.fromtimestamp(p.time)}")
        print(f"Interface:\t{p.sniffed_on}")
        
        proto_name = p.sprintf("%IP.proto%").upper()
        if proto_name == "??":
            proto_name = "NON-IP"

        print(f"Protocol:\t{proto_name}")
        print(f"MAC Source:\t{p.src}")
        print(f"MAC Dest:\t{p.dst}")

        if IP in p:
            ip_src = p[IP].src
            ip_dst = p[IP].dst
            print(f"IP Source:\t{ip_src}")
            print(f"IP Dest:\t{ip_dst}")
        if TCP in p:
            tcp_src = p[TCP].sport
            tcp_dst = p[TCP].dport
            print(f"TCP Source:\t{tcp_src}")
            print(f"TCP Dest:\t{tcp_dst}")

        print(f"Length:\t\t{len(p)}")
        print(f"Content:\t{p.summary()}")
        print(f"Content:\t{p.sprintf('%IP.payload%')}")



        i += 1

