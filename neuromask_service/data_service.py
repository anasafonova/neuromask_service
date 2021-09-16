import socket
import subprocess
from logger import Logger

class BasicService():

    def __init__(self, logger: Logger, host: str, port: int, base_path: str, batch_size: int, num_files: int, rotate_time: int):
        self.logger = logger
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.clients_list = []
        self.batch_size = batch_size
        self.rotate_time = rotate_time
        self.num_files = num_files
        self.base_path = base_path

        self.logger.log("Service inited", level='debug')

    def listen(self):
        subprocess.Popen(
            f'tcpdump -C {self.batch_size} -G {self.rotate_time} ' +
            f'-W {self.num_files} -i any -n udp port {self.port} ' +
            f'-w {self.base_path + "/neuromask.pcap"} -Z root',
            shell=True, close_fds=True)
        self.logger.log("Start listening", level='info')