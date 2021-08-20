import logging
import binascii
import struct

class BasicTransformer:
    def __init__(self, *args, **kwargs):
        logging.info('Initializing Transformer')

    def parse_packet(self, packet):
        logging.info("Received: %s", packet)
        data = {}
        if ((binascii.hexlify(packet[:2]) == b'f0aa') and (binascii.hexlify(packet[-2:]) == b'f1aa')):
            logging.info("Packet is correct")
            length = int.from_bytes(packet[2:4], byteorder='little', signed=False)
            if (length == (len(packet) - 6)):
                logging.info("Length is correct")
                i = 0
                num_packets = (length - 4) / 5
                _time = int.from_bytes(packet[4 + i:4 + i +4], byteorder='little', signed=False)
                data["_time"] = _time
                data["host"] = host
                while i < num_packets:
                    sensor = sensor_dict[int.from_bytes(packet[8+i*5:9+i*5], byteorder='little', signed=False)]
                    sensor_value = struct.unpack('f', packet[9+i*5:9+i*5+4])
                    data[sensor] = sensor_value[0]
                    i += 1
                logging.info("%s", data)
            else:
                logging.info("incorrect length")
        else:
            logging.info("incorrect packet")
        return data

    def extractData(self, packet, packets=10):


    def saveData(self, packet):


    def transform(self):
