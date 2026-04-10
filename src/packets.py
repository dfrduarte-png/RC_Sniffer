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

def print_packets(packets: PacketList):
    for i, p in enumerate(packets, 1):
        # Create an internal table for alignment
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Key", style="cyan", justify="right", width=15)
        table.add_column("Value", style="white")

        table.add_row("Arrival time", datetime.fromtimestamp(float(p.time)).strftime('%H:%M:%S'))
        table.add_row("Interface", str(p.sniffed_on))
        table.add_row("Protocol", f"[bold yellow]{get_protocol_name(p)}[/bold yellow]")
        
        table.add_row("Source MAC", str(p.src))
        table.add_row("Dest MAC", str(p.dst))

        if IP in p:
            table.add_row("Source IP", p[IP].src)
            table.add_row("Dest IP", p[IP].dst)
        elif IPv6 in p:
            table.add_row("Source IP", p[IPv6].src)
            table.add_row("Dest IP", p[IPv6].dst)

        if TCP in p:
            table.add_row("TCP Source", str(p[TCP].sport))
            table.add_row("TCP Dest", str(p[TCP].dport))
        elif UDP in p:
            table.add_row("UDP Source", str(p[UDP].sport))
            table.add_row("UDP Dest", str(p[UDP].dport))

        table.add_row("Length", f"{len(p)} bytes")
        
        last_layer = p.lastlayer()
        summary = last_layer.summary() if last_layer else "No summary"
        table.add_row("Content", f"[bold green]{summary}[/bold green]")

        # expand=True ensures all panels take the full terminal width
        console.print(Panel(table, title=f"[bold blue]Packet {i}[/bold blue]", expand=True))
