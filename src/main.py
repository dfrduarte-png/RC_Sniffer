from interfaces import get_ifs
from sniffer import Sniffer
from packets import print_packets
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich import box

console = Console(emoji=False)

def pause():
    """Waits for the user to press ENTER before clearing the screen."""
    Prompt.ask("\n[bold cyan]Press ENTER to continue[/bold cyan]", default="", show_default=False)
    console.clear()

def display_menu():
    """Displays the main menu using a Rich Panel."""
    menu_text = (
        "[bold cyan][1][/bold cyan] Select network interface\n"
        "[bold cyan][2][/bold cyan] Capture packets\n"
        "[bold cyan][3][/bold cyan] Quit"
    )
    console.print(Panel(menu_text, title="[bold magenta]Sniffer Menu[/bold magenta]", expand=False))

def select_if(sniffer: Sniffer):
    """Lists available interfaces in a table and prompts for selection."""
    ifs = get_ifs()
    
    table = Table(title="[bold blue]Available Network Interfaces[/bold blue]", box=box.SIMPLE)
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Interface Name", style="white")

    for idx, interface in enumerate(ifs, 1):
        table.add_row(str(idx), interface)

    console.print(table)

    choices = [str(i) for i in range(1, len(ifs) + 1)]
    ans = IntPrompt.ask("Select the desired interface ID", choices=choices)
    
    sniffer.interface = ifs[ans - 1]
    console.print(f"[bold green]Selected interface:[/bold green] [white]{sniffer.interface}[/white]")
    pause()

def sniffer_sniff(sniffer: Sniffer):
    """Prompts for filters and count, then executes the sniff."""
    if not sniffer.valid_interface():
        console.print("[bold red][ERROR][/bold red] No interface selected. Please select one first.")
        pause()
        return

    filter_val = Prompt.ask("Input a BPF filter (e.g., 'tcp', 'port 80')", default="")
    count_val = IntPrompt.ask("Input packet count", default=10)

    sniffer.filter = filter_val
    sniffer.count = count_val
 
    console.print(f"\n[bold green]Starting capture on {sniffer.interface}...[/bold green]")
    
    # Run the status spinner only during the actual capture
    with console.status("[bold yellow]Sniffing...[/bold yellow]"):
        try:
            packets = sniffer.sniff_packets()
        except Exception as e:
            console.print(f"[bold red][ERROR][/bold red] {e}")
            pause()
            return
            
    # Print boxes after the spinner is gone to avoid visual glitches
    print_packets(packets)
    pause()

def main():
    sniffer = Sniffer()
    console.clear()

    while True:
        display_menu()
        
        ans = Prompt.ask("Select an option", choices=["1", "2", "3"])

        if ans == "1":
            select_if(sniffer)
        elif ans == "2":
            sniffer_sniff(sniffer)
        elif ans == "3":
            console.print("[bold cyan]Goodbye![/bold cyan]")
            break

if __name__ == "__main__":
    main()
