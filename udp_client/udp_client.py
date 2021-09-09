import socket
import binascii
import time
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

content = []
config_data = {}

with open('config.json', 'r') as config_file:
    config_data = json.load(config_file)

with open('neuromask_.bin', 'rb') as fin:
    contents = binascii.hexlify(fin.read())
    sep = b'f1aa'
    cnts = contents.split(sep)
    content = [ s + "f1aa".encode() for s in cnts if len(s) > 0 ]
    content = [ binascii.unhexlify(s) for s in content ]

while True:
    i = 0
    for msg in content:
        print(msg)
        sock.sendto(msg, (config_data['host'], config_data['port']))
    #    i += 1
    #     time.sleep(0.1)
    #     if (i == 1):
    #         break
    # if (i == 1):
    #     break
    time.sleep(1)

sock.close()