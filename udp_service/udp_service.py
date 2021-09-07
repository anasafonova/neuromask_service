import logging
import socket
import binascii
from threading import Thread
import subprocess
from config import import_config

class UdpService():
    def __init__(self):
        logging.info('Initializing Process')
        conf = import_config('config.json')
        self.host = conf.get('connection', {}).get('host')
        self.port = conf.get('connection', {}).get('port')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.clients_list = []
        self.threads = []
        self.inputfile_size = conf.get('tcpdump', {}).get('batchsize')
        self.inputfile_rotate_time = conf.get('tcpdump', {}).get('rotate_time')
        self.inputfile_num = conf.get('tcpdump', {}).get('num_files')
        self.inputpath = conf.get('paths', {}).get('rawpath')
        subprocess.Popen(
            f'tcpdump -C {self.inputfile_size} -G {self.inputfile_rotate_time} ' +
            f'-W {self.inputfile_num} -i any -n udp port {self.port} ' +
            f'-w {self.inputpath} -Z root',
            shell=True, close_fds=True)

    def get_packet(self, client, msg):
        with open('neuromask.bin', 'ab') as fout:
            fout.write(msg)
        hex = binascii.hexlify(msg)
        logging.info('%s', self.clients_list)
        logging.info('Received data from client %s: %s', client, hex)

    def listen_clients(self):
        while True:
            msg, client = self.sock.recvfrom(1024)
            if client not in self.clients_list:
                self.clients_list.append(client)

            thread = Thread(target=self.get_packet, args=(client, msg,))
            thread.start()
            self.threads.append(thread)


if __name__ == '__main__':
    # Make sure all log messages show up
    logging.getLogger().setLevel(logging.DEBUG)

    b = UdpService()
    b.listen_clients()