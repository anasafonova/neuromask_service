from scapy.all import *
import logging
import binascii
import os
import struct
import json
from config import import_config

from scapy.layers.inet import UDP

#num_files = 69
num_packets = 0
outfile_num = 0
date = 0
#num_files = 0 #conf.get('tcpdump', {}).get('num_files')
#inpath = 'in/neurodata_20210813.pcap'
#outpath = 'out/data'

sensor_dict = {16: "eco2", 17: "o2", 18: "t_body", 19: "humidity",
        20: "tvoc", 21: "pressure", 22: "t_ext", 23: "ecg",
        24: "ax", 25: "ay", 26: "az", 27: "gx", 28: "gy",
        29: "gz", 30: "mx", 31: "my", 32: "mz", 33: "spo2_red",
        34: "spo2_ir", 35: "spo2_green", 36: "spo2_lvl",
        37: "alt", 38: "hr", 39: "steps", 40: "pwr_lvl",
        41: "tvoc_ext", 42: "eco2_ext", 43: "hum_ext" }

def is_packet(packet):
    return

def check_length(packet):
    return

def check_value(comment, value, expected):
    if value == expected:
        logging.info("%s is correct" % comment)
        return True
    else:
        logging.info("%s - error" % comment)
        return False

def get_value(field, cursor):
    if field["type"] == "int":
        return (int.from_bytes(packet[cursor:cursor + field["len"]],
                               byteorder='little', signed=False),
                cursor + field["len"])
    elif field["type"] == "str":
        return (binascii.hexlify(packet[cursor:cursor + field["len"]]),
                cursor + field["len"])
    elif field["type"] == "float":
        return (struct.unpack('f', packet[cursor:cursor + field["len"]]),
                cursor + field["len"])
    elif field["type"] == "dict":
        return (sensor_dict.get(
            int.from_bytes(packet[cursor:cursor + field["len"]], byteorder='little', signed=False)),
                cursor + field["len"])

def parse_packet_data(packet, host, struct_conf):
    packet_struct = struct_conf.get('packet_struct')
    #logging.info(packet_struct)
    logging.info("Received: %s", packet)
    data = {}
    cols = ['_time', 'host']
    if has_mac:
        cols.extend(['mac_address'])
    cols.extend(sensor_dict.values())

    cursor = 0

    if not host:
        data["host"] = host

    for field in packet_struct:
        if field["data"]:
            if field["required"]:
                (value, cursor) = get_value(field, cursor)
                logging.info(field, " ", cursor)
                if "expected" in field.keys():
                    if not check_value(field["_comment"], value, field["expected"]):
                        break
                if field["to_df"]:
                    data[field["name"]] = value
        else:
            if field["purpose"] == "loop":
                if field["loop_type"] in field.keys():
                    cmd = field["loop_type"] + field["decreased_value"] + ":"
                    print(cmd)
                    exec(cmd)



def parse_data(packet, host, has_mac):
    logging.info("Received: %s", packet)
    data = {}
    cols = ['_time', 'host']
    if has_mac:
        cols.extend(['mac_address'])
    cols.extend(sensor_dict.values())
    if ((binascii.hexlify(packet[:2]) == b'f0aa') and (binascii.hexlify(packet[-2:]) == b'f1aa')):
        logging.info("Packet is correct")
        length = int.from_bytes(packet[2:4], byteorder='little', signed=False)
        if (length == (len(packet) - 6)):
            logging.info("Length is correct")
            i = 0
            num_packets = (length - 7) / 5
            if has_mac:
                mac = int.from_bytes(packet[4 + i:4 + i + 3], byteorder='little', signed=False)
                data["mac_address"] = mac
            _time = int.from_bytes(packet[7 + i:7 + i + 4], byteorder='little', signed=False)
            data["_time"] = _time
            data["host"] = host
            while i < num_packets:
                sensor = sensor_dict.get(int.from_bytes(packet[11 + i * 5:12 + i * 5], byteorder='little', signed=False))
                sensor_value = struct.unpack('f', packet[12 + i * 5:12 + i * 5 + 4])
                data[sensor] = sensor_value[0]
                i += 1
            logging.info("%s", data)
        else:
            logging.info("incorrect length")
    else:
        logging.info("incorrect packet")

    return data

def read_data(finpath, foutpath, struct_conf):
    global num_packets

    with open(foutpath, 'a+') as fout:
        logging.info(finpath)
        if os.path.exists(finpath):
            scapy_cap = rdpcap(finpath)
            if len(scapy_cap) > num_packets:
                for j in range(num_packets, len(scapy_cap)):
                    packet = scapy_cap[j]
                    try:
                        packet.show()
                        host = ""
                        if IP in packet:
                            host = packet[IP].src+":"
                        if UDP in packet:
                            host += str(packet[UDP].sport)
                        logging.info("Received packet from: %s\nPayload: %s", host, binascii.hexlify(bytes(packet[UDP].payload)))
                        data = parse_packet_data(bytes(packet[UDP].payload), host, struct_conf)
                        if num_packets > 0:
                            fout.write(' , ')
                        json.dump(data, fout)
                    except Scapy_Exception:
                        pass
                    num_packets += 1

if __name__ == '__main__':
    # Make sure all log messages show up
    logging.getLogger().setLevel(logging.DEBUG)
    conf = import_config('config.json')

    inpath = conf.get('paths', {}).get('rawpath')
    outpath = conf.get('paths', {}).get('jsonpath')
    num_files = conf.get('tcpdump', {}).get('num_files')
    file_size = conf.get('tcpdump', {}).get('batchsize')*1000000
    row_count = conf.get('output', {}).get('row_count')
    struct_path = conf.get('paths', {}).get('packet_struct')
    struct_conf = import_config(struct_path)

    while True:
        i = 0
        while i < 1: #num_files:
            finpath = inpath + '{:02d}'.format(i)
            foutpath = outpath + '{:02d}'.format(i) + ".json"
            read_data(finpath, foutpath, struct_conf)
            # while os.path.getsize(finpath) < file_size - 50:
            #     time.sleep(5)
            # if os.path.getsize(finpath) >= file_size - 50:
            #     num_packets = 0
            #     read_data(finpath, foutpath, has_mac)
            # i += 1
            # if i == num_files:
            #     i = 0
            # time.sleep(1)
