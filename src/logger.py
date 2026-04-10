import os
import json
import csv
from datetime import datetime
from scapy.all import wrpcap, PacketList
from packets import packet_to_dict

class Logger:
    AVAILABLE_TYPES = ["pcap", "csv", "txt", "json"]

    def __init__(self):
        self.__status = False
        self.__filetypes = ["pcap"]
        self.__logdir = "./logs"

    @property
    def status(self) -> bool:
        return self.__status

    @status.setter
    def status(self, value: bool):
        if not isinstance(value, bool):
            raise ValueError("Status must be a boolean.")
        self.__status = value

    @property
    def filetypes(self) -> list:
        return self.__filetypes

    @filetypes.setter
    def filetypes(self, values: list):
        if not isinstance(values, list):
            raise ValueError("Filetypes must be a list.")
        for v in values:
            if v not in self.AVAILABLE_TYPES:
                raise ValueError(f"Invalid file type: {v}. Must be one of {self.AVAILABLE_TYPES}")
        self.__filetypes = values

    @property
    def logdir(self) -> str:
        return self.__logdir

    @logdir.setter
    def logdir(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Log directory must be a string.")
        self.__logdir = value

    def __create_dir(self):
        """Ensures the log directory exists."""
        os.makedirs(self.__logdir, exist_ok=True)

    def __create_filename(self, filetype: str, timestamp: str) -> str:
        """Generates a standardized filename for a session."""
        return os.path.join(self.__logdir, f"session_{timestamp}.{filetype}")

    def log_packets(self, packets: PacketList):
        """Logs the packet list to all selected file formats."""
        if not self.__status or not packets:
            return

        self.__create_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Pre-convert to dictionaries for text-based formats
        packet_dicts = [packet_to_dict(p) for p in packets]

        for ft in self.__filetypes:
            filename = self.__create_filename(ft, timestamp)
            try:
                if ft == "pcap":
                    wrpcap(filename, packets)
                elif ft == "json":
                    with open(filename, "w") as f:
                        json.dump(packet_dicts, f, indent=4)
                elif ft == "csv":
                    if packet_dicts:
                        with open(filename, "w", newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=packet_dicts[0].keys())
                            writer.writeheader()
                            writer.writerows(packet_dicts)
                elif ft == "txt":
                    with open(filename, "w") as f:
                        for i, d in enumerate(packet_dicts, 1):
                            f.write(f"--- Packet {i} ---\n")
                            for k, v in d.items():
                                f.write(f"{k}: {v}\n")
                            f.write("\n")
            except Exception as e:
                print(f"[LOGGER ERROR] Failed to save {ft}: {e}")
