from scapy.all import PacketList, sniff

class Sniffer:
    def __init__(self):
        self.__interface = ""
        self.__filter = ""
        self.__count = 10

    @property
    def interface(self) -> str:
        return self.__interface

    @interface.setter
    def interface(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Interface must be a string.")
        self.__interface = value

    @property
    def filter(self) -> str:
        return self.__filter

    @filter.setter
    def filter(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Filter must be a string.")
        self.__filter = value 

    @property
    def count(self) -> int:
        return self.__count
    
    @count.setter
    def count(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Count must be an integer.")
        self.__count = value

    def valid_interface(self) -> bool:
        return self.interface != ""

    def sniff_packets(self) -> PacketList:
        return sniff(iface=self.interface, filter=self.filter, count=self.count, prn=lambda x: x.summary()) 


        
