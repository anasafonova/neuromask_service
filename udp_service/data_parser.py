import binascii
import struct
from logger import Logger
from scapy.layers.inet import UDP, IP
from scapy.all import *


class BasicParser:

    def __init__(self, logger: Logger, sensors: dict, pattern=None):
        if pattern is None:
            pattern = []
        self.logger = logger
        self.sensors = sensors
        self.pattern = pattern  # To be used with packet_struct pattern

        self.logger.log("Parser inited", level='debug')

    @staticmethod
    def is_float(value):
        try:
            float(value)
            return True
        except ValueError:
            return False

    def check_value(self, comment, value, expected):
        if value == expected:
            self.logger.log(f'{comment} is correct')
            return True
        else:
            self.logger.log(f'{comment} is not valid', value=value, expected=expected, level="error")
            return False

    @staticmethod
    def prettify(mac_string):
        return ':'.join('%02x' % ord(b) for b in mac_string)

    def get_value(self, packet, _type, _len, cursor):
        if _type == "int":
            return (int.from_bytes(packet[cursor:cursor + _len],
                                   byteorder='little', signed=False),
                    cursor + _len)
        elif _type == "str":
            return (binascii.hexlify(packet[cursor:cursor + _len]),
                    cursor + _len)
        elif _type == "float":
            val = struct.unpack('f', packet[cursor:cursor + _len])
            return (val[0],
                    cursor + _len)
        elif _type == "dict":
            return (self.sensors.get(
                str(int.from_bytes(packet[cursor:cursor + _len], byteorder='little', signed=False))),
                    cursor + _len)
        elif _type == "hex":
            a = (b'b8f009' + binascii.hexlify(packet[cursor:cursor + _len])).decode("ascii")
            return (a,  # prettify(a),
                    cursor + _len)

    def parse_packet(self, scapy_packet):
        result = {}
        self.logger.log(f'Received: {scapy_packet}', level='debug')

        try:
            host = ""
            if IP in scapy_packet:
                host = scapy_packet[IP].src + ":"
            if UDP in scapy_packet:
                host += str(scapy_packet[UDP].sport)
            self.logger.log(f"Received packet", host=host)
            result = self.parse_payload(bytes(scapy_packet[UDP].payload))
            result["host"] = host
        except Scapy_Exception as e:
            self.logger.log(e, level='error')
            pass

        return result

    def parse_payload(self, packet):
        packet_struct = self.pattern
        cursor = 0

        data = {}
        cols = ['_time']

        for field in packet_struct:
            val = field.get('_comment')
            if val == "mac_address":
                cols.extend(['mac_address'])

        cols.extend(self.sensors.values())

        k = 0
        while k < len(packet_struct):
            field = packet_struct[k]
            t_max = 0
            if field["purpose"] == "loop":
                if field.get('decreased_value'):
                    cond = eval(field["decreased_value"])
                    self.logger.log(f'Condition {field.get("decreased_value")}, {cond}')
                    j = 0
                    index = packet_struct.index(field)
                    t = 1
                    field_name = " "
                    while j < cond:
                        field_ = packet_struct[index + t]
                        if field_["data"]:
                            if field_["required"]:
                                # self.logger.log(
                                #     f"Value: {int.from_bytes(packet[cursor:cursor + field_['len']], byteorder='little', signed=False)}",
                                # )
                                (value, cursor) = self.get_value(packet, field_["type"], field_["len"], cursor)
                                self.logger.log(f'Got data', value=value, pos=cursor, level="debug")
                                if "expected" in field_.keys():
                                    expected = field_["expected"]
                                    if not self.is_float(field_["expected"]):
                                        expected = eval(field_["expected"])
                                    if not self.check_value(field_["_comment"], value, expected):
                                        break
                                if field_["to_df"]:
                                    if field_["name"] == "key":
                                        field_name = value
                                    elif field_["name"] != "value":
                                        field_name = field_["name"]
                                    data[field_name] = value
                        elif field_["purpose"] == "loop":
                            j += 1
                            t_max = packet_struct.index(field_)
                            t = 0
                        t += 1

                    k = t_max + 1

            elif field["data"]:
                if field["required"]:
                    (value, cursor) = self.get_value(packet, field["type"], field["len"], cursor)
                    self.logger.log(f'Data: {value}, {cursor}', level="debug")
                    self.logger.log(f'Data: {packet[cursor:cursor + field["len"]]}')
                    self.logger.log(f'Data: {value}, {cursor}', level="debug")
                    if "expected" in field.keys():
                        expected = field["expected"]
                        if not self.is_float(field["expected"]):
                            expected = eval(field["expected"])
                        if not self.check_value(field["_comment"], value, expected):
                            break
                    if field["to_df"]:
                        data[field["name"]] = value
                k += 1

        self.logger.log(f'Data: {data}')
        return data
