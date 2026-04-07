from scapy.all import sniff
from interfaces import get_ifs
from sniffer import Sniffer


def menu():
    print("Avaliable options:")
    print("[1] Select network interface")
    print("[2] Capture packets")
    print("[3] Quit")

def select_if(sniffer: Sniffer):
    ifs = get_ifs()
    
    idx = 1
    print("Avaliable neywork interfaces:")
    for i in ifs:
        print(f"[{idx}] {i}")
        idx += 1

    ans = input("Select the desired interface:\n>")
    try:
        ans = int(ans) - 1
    except Exception as e:
        print("[ERROR] Invalid option.")

    sniffer.interface = ifs[ans]
    print(f"Selected interface: {sniffer.interface}")
    
def sniffer_sniff(sniffer: Sniffer):
    if not sniffer.valid_interface():
        print("[ERROR] Sniffer's set interface is invalid. PLease set it up correctly")
        return

    filter = input("Input a filter (ENTER for no filter):\n> ")
    count = input("Input how many packets to capture (ENTER for deafult 10):\n> ")

    sniffer.filter = filter
    if count.strip() != "":
        try:
            sniffer.count = int(count)
        except Exception as e:
            print("[ERROR] Count must be an integer.")
            return
 
    packets = sniffer.sniff_packets()


def main():
    run = True
    sniffer = Sniffer()

    while(run):
        menu()
    
        ans = input("Select an option:\n> ")
        try:
            ans = int(ans)
        except Exception as e:
            print("[ERROR] Invalid option.")

        match ans:
            case 1:
                select_if(sniffer) 
            case 2:
                sniffer_sniff(sniffer)
            case 3:
                run = False;




    

    

if __name__ == "__main__":
    main()
