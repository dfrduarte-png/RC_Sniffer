from interfaces import get_ifs
from sniffer import Sniffer
from logger import Logger
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

def display_menu(logger: Logger):
    """Displays the main menu with a visual Logger indicator."""
    status_color = "green" if logger.status else "red"
    status_text = "ACTIVE" if logger.status else "INACTIVE"
    
    # Visual status indicator in the Panel title
    title = f"[bold magenta]Sniffer Menu[/bold magenta] [bold {status_color}][LOGGER: {status_text}][/bold {status_color}]"
    
    menu_text = (
        "[bold cyan][1][/bold cyan] Select network interface\n"
        "[bold cyan][2][/bold cyan] Capture packets\n"
        "[bold cyan][3][/bold cyan] Configure Logger\n"
        "[bold cyan][4][/bold cyan] Quit"
    )
    console.print(Panel(menu_text, title=title, expand=False))

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

def configure_logger(logger: Logger):
    """Configuration menu for the Logger."""
    console.clear()
    console.print(Panel("[bold yellow]Logger Configuration[/bold yellow]", expand=False))
    
    # Toggle Status
    toggle = Prompt.ask("Enable Logger?", choices=["y", "n"], default="y" if logger.status else "n")
    logger.status = (toggle == "y")
    
    if logger.status:
        # Select Multiple Filetypes
        console.print(f"\nAvailable filetypes: [cyan]{', '.join(logger.AVAILABLE_TYPES)}[/cyan]")
        ft_input = Prompt.ask("Enter filetypes separated by commas", default=",".join(logger.filetypes))
        selected_types = [t.strip().lower() for t in ft_input.split(",") if t.strip()]
        
        try:
            logger.filetypes = selected_types
        except ValueError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            logger.filetypes = ["pcap"]

        # Select Log Directory
        dir_input = Prompt.ask("Enter log directory path", default=logger.logdir)
        logger.logdir = dir_input
    
    console.print("\n[bold green]Logger configuration updated![/bold green]")
    pause()

def sniffer_sniff(sniffer: Sniffer, logger: Logger):
    """Prompts for filters and count, then executes the sniff and logs if enabled."""
    if not sniffer.valid_interface():
        console.print("[bold red][ERROR][/bold red] No interface selected. Please select one first.")
        pause()
        return

    filter_val = Prompt.ask("Input a BPF filter (e.g., 'tcp', 'port 80')", default="")
    count_val = IntPrompt.ask("Input packet count", default=10)

    sniffer.filter = filter_val
    sniffer.count = count_val
 
    console.print(f"\n[bold green]Starting capture on {sniffer.interface}...[/bold green]")
    
    with console.status("[bold yellow]Sniffing...[/bold yellow]"):
        try:
            packets = sniffer.sniff_packets()
        except Exception as e:
            console.print(f"[bold red][ERROR][/bold red] {e}")
            pause()
            return
            
    print_packets(packets)
    
    # Log the packets if the logger is enabled
    if logger.status:
        with console.status("[bold blue]Logging session...[/bold blue]"):
            logger.log_packets(packets)
        console.print(f"[bold green]Session logged in formats:[/bold green] [white]{', '.join(logger.filetypes)}[/white]")
        console.print(f"[bold green]Path:[/bold green] [white]{logger.logdir}[/white]")
    
    pause()

def main():
    sniffer = Sniffer()
    logger = Logger()
    console.clear()

    while True:
        display_menu(logger)
        
        ans = Prompt.ask("Select an option", choices=["1", "2", "3", "4"])

        if ans == "1":
            select_if(sniffer)
        elif ans == "2":
            sniffer_sniff(sniffer, logger)
        elif ans == "3":
            configure_logger(logger)
        elif ans == "4":
            console.print("[bold cyan]Goodbye![/bold cyan]")
            break

if __name__ == "__main__":
    main()
