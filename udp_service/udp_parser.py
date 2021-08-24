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
packet_len = 0
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

def isfloat(value):
  try:
    float(value)
    return True
  except ValueError:
    return False

def check_value(comment, value, expected):
    global packet_len
    if comment == "length":
        packet_len = value
    if value == expected:
        logging.info("%s is correct" % comment)
        return True
    else:
        logging.info("%s - error" % comment)
        return False

def get_value(packet, type, len, cursor):
    if type == "int":
        return (int.from_bytes(packet[cursor:cursor + len],
                               byteorder='little', signed=False),
                cursor + len)
    elif type == "str":
        return (binascii.hexlify(packet[cursor:cursor + len]),
                cursor + len)
    elif type == "float":
        val = struct.unpack('f', packet[cursor:cursor + len])
        return (val[0],
                cursor + len)
    elif type == "dict":
        return (sensor_dict.get(
            int.from_bytes(packet[cursor:cursor + len], byteorder='little', signed=False)),
                cursor + len)

def parse_packet_data(packet, host, struct_conf):
    packet_struct = struct_conf.get('packet_struct')
    #logging.info(packet_struct)
    logging.info("Received: %s", packet)
    data = {}
    cols = ['_time', 'host']

    for field in packet_struct:
        val = field.get('_comment')
        if val == "mac_address":
            cols.extend(['mac_address'])

    cols.extend(sensor_dict.values())

    cursor = 0

    #if host != "":
    data["host"] = host

    k = 0
    while k < len(packet_struct):
        field = packet_struct[k]
        t_max = 0
        if field["purpose"] == "loop":
            if any(field.get('decreased_value')):
                cond = eval(field["decreased_value"])
                logging.info("Condition %s %s", field["decreased_value"], cond)
                j = 0
                index = packet_struct.index(field)
                t = 1
                field_name = " "
                while j < cond:
                    field_ = packet_struct[index + t]
                    if field_["data"]:
                        if field_["required"]:
                                (value, cursor) = get_value(packet, field_["type"], field_["len"], cursor)
                                logging.info("Data: %s, %i", value, cursor)
                                if "expected" in field_.keys():
                                    expected = field_["expected"]
                                    if not isfloat(field_["expected"]):
                                        expected = eval(field_["expected"])
                                    if not check_value(field_["_comment"], value, expected):
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
                logging.info("Data: %s, %i", field, cursor)
                logging.info("Data: %s", packet[cursor:cursor+field["len"]])
                (value, cursor) = get_value(packet, field["type"], field["len"], cursor)
                logging.info("Data: %s, %i", value, cursor)
                if "expected" in field.keys():
                    expected = field["expected"]
                    if not isfloat(field["expected"]):
                        expected = eval(field["expected"])
                    if not check_value(field["_comment"], value, expected):
                        break
                if field["to_df"]:
                    data[field["name"]] = value
            k += 1


    logging.info("Data: %s", data)
    return data


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

def read_data(finpath, common_foutpath, struct_conf, row_count):
    global num_packets
    #num_packets = 0

    delta = (num_packets - num_packets % row_count) / row_count
    foutpath = common_foutpath + str(delta)

    with open(foutpath, 'a+') as fout:
        logging.info(finpath)
        if os.path.exists(finpath):
            scapy_cap = rdpcap(finpath)
            logging.info(len(scapy_cap))
            if len(scapy_cap) > num_packets:
                for j in range(num_packets, num_packets + len(scapy_cap)):
                    packet = scapy_cap[j]
                    if j == 10:
                        break
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
                        num_packets += 1
                    except Scapy_Exception:
                        pass

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
        while i < 2: #num_files:
            finpath = inpath + '{:02d}'.format(i)
            foutpath = outpath + '{:02d}'.format(i) + ".json"
            read_data(finpath, foutpath, struct_conf, row_count)
            i += 1
        if i == 2:
            break

            # while os.path.getsize(finpath) < file_size - 50:
            #     time.sleep(5)
            # if os.path.getsize(finpath) >= file_size - 50:
            #     num_packets = 0
            #     read_data(finpath, foutpath, has_mac)
            # i += 1
            # if i == num_files:
            #     i = 0
            # time.sleep(1)
