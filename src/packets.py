from datetime import datetime
from scapy.all import Packet, PacketList, IP, TCP, UDP, IPv6
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Initializing Console with emoji=False globally disables emoji rendering
console = Console(emoji=False)

def get_protocol_name(p: Packet) -> str:
    """Identifies the most specific protocol name, prioritizing error protocols."""
    if "ICMP" in p:
        return "ICMP"
        
    layers = p.layers()
    if not layers:
        return "UNKNOWN"
    
    last_layer = p.getlayer(layers[-1])
    if last_layer is None:
        return "UNKNOWN"
        
    name = str(last_layer.name)

    if name in ["Raw", "Padding"] and len(layers) > 1:
        prev_layer = p.getlayer(layers[-2])
        if prev_layer:
            name = str(prev_layer.name)

    name = name.upper()
    return "DHCP" if "DHCP" in name else name

def packet_to_dict(p: Packet) -> dict:
    """Extracts all packet fields into a dictionary for consistent printing and logging."""
    data = {
        "Arrival time": datetime.fromtimestamp(float(p.time)).strftime('%Y-%m-%d %H:%M:%S'),
        "Interface": str(p.sniffed_on),
        "Protocol": get_protocol_name(p),
        "Source MAC": str(p.src),
        "Dest MAC": str(p.dst),
    }

    # Handle Network Layer (IPv4/IPv6)
    if IP in p:
        data["Source IP"] = str(p[IP].src)
        data["Dest IP"] = str(p[IP].dst)
    elif IPv6 in p:
        data["Source IP"] = str(p[IPv6].src)
        data["Dest IP"] = str(p[IPv6].dst)

    # Handle Transport Layer (TCP/UDP)
    if TCP in p:
        data["TCP Source"] = str(p[TCP].sport)
        data["TCP Dest"] = str(p[TCP].dport)
    elif UDP in p:
        data["UDP Source"] = str(p[UDP].sport)
        data["UDP Dest"] = str(p[UDP].dport)

    data["Length"] = f"{len(p)} bytes"
    
    last_layer = p.lastlayer()
    data["Content"] = last_layer.summary() if last_layer else "No summary"
    
    return data

def print_packets(packets: PacketList):
    """Prints packets in a beautiful, uniform layout using Rich."""
    for i, p in enumerate(packets, 1):
        packet_data = packet_to_dict(p)
        
        # Create an internal table for alignment
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Key", style="cyan", justify="right", width=15)
        table.add_column("Value", style="white")

        for key, value in packet_data.items():
            # Special styling for specific fields
            if key == "Protocol":
                table.add_row(key, f"[bold yellow]{value}[/bold yellow]")
            elif key == "Content":
                table.add_row(key, f"[bold green]{value}[/bold green]")
            else:
                table.add_row(key, value)

        # expand=True ensures all panels take the full terminal width
        console.print(Panel(table, title=f"[bold blue]Packet {i}[/bold blue]", expand=True))
