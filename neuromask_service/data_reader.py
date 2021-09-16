from pathlib import Path
from scapy.all import *
from logger import Logger

class DataReader:

    def __init__(self, logger: Logger, base_dir: str, file_size: int, delete_files=True):
        self.logger = logger
        self.base_dir = Path(base_dir)
        self.delete_files = delete_files
        self.file_size = file_size

        self.logger.log("Reader inited", level='debug')

    def _is_file_completed(self, _file: Path):
        return True  # TODO implement!

    def read_data(self):

        result = []

        for _file in Path.glob(self.base_dir, "*.pcap*"):
            if self._is_file_completed(_file):
                packets = self.read_file(_file)
                if packets:
                    result += packets
                try:
                    if self.delete_files:
                        _file.unlink()
                except:
                    pass
            break

        return result

    def read_file(self, file_path: Path):

        if file_path.is_file() and file_path.exists():
            self.logger.log("Reading file", file_name=file_path.name, level='debug')
            try:
                scapy_cap = rdpcap(file_path.as_posix())
                self.logger.log(f"Packets num: {len(scapy_cap)}", file_name=file_path.name, level='debug')
                return scapy_cap
            except Exception as e:
                self.logger.log(e, level='error')
                return []

