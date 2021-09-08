import binascii
import struct


class BasicParser:

    def __init__(self, logger, sensors: dict, pattern=None):
        self.logger = logger
        self.sensors = sensors
        self.pattern = pattern  # To be used with packet_struct pattern

    @staticmethod
    def _are_flags_correct(packet):
        return (binascii.hexlify(packet[:2]) == b'f0aa') and (binascii.hexlify(packet[-2:]) == b'f1aa')

    @staticmethod
    def _get_length(packet):
        return int.from_bytes(packet[2:4], byteorder='little', signed=False)

    @staticmethod
    def _is_length_correct(length, packet):
        return length == (len(packet) - 6)

    @staticmethod
    def _get_time(packet):
        return int.from_bytes(packet[4:8], byteorder='little', signed=False)

    def parse_packet(self, packet):
        self.logger.info("Received: %s", packet)

        result = {}

        if self._are_flags_correct(packet):
            self.logger.info("Packet is correct")

            length = self._get_length(packet)

            if self._is_length_correct(length, packet):
                self.logger.info("Length is correct")

                result["_time"] = self._get_time(packet)

                i = 0
                num_packets = (length - 4) / 5

                while i < num_packets:
                    sensor = self.sensors.get(
                        int.from_bytes(packet[8+i*5:9+i*5], byteorder='little', signed=False), "undefined"
                    )
                    sensor_value = struct.unpack('f', packet[9+i*5:9+i*5+4])
                    result[sensor] = sensor_value[0]
                    i += 1

                self.logger.info("%s", result)

            else:
                self.logger.info("incorrect length")
        else:
            self.logger.info("incorrect packet")

        return result
