from time import sleep
from multiprocessing import Process

from data_parser import BasicParser
from data_reader import DataReader
from data_writer import DataWriter
from logger import logger
from config import import_config


def process_packets(conf, packets):
    parser = BasicParser(
        logger,
        sensors=conf.get('sensors'),
        pattern=conf.get('pattern')
    )
    writer = DataWriter(
        logger,
        base_dir=conf.get('paths', {}).get('jsonpath'),
        batch_length=10000
    )

    for packet in packets:
        data = parser.parse_packet(packet)
        writer.write_line(data)


def main(config_file):
    conf = import_config(config_file)
    logger.set_logger(
        **conf.get('logging')
    )
    logger.log("Logger inited.")

    reader = DataReader(
        logger,
        base_dir=conf.get('paths', {}).get('rawpath'),
        file_size=1000000,
        delete_files=True
    )

    cores = conf.get('cores', 0)

    while 1:
        if cores > 1:
            procs = []
            for _ in range(conf.get('cores', 1)):
                packets = reader.read_data()
                p = Process(target=process_packets, args=(conf, packets))
                p.start()
                procs.append(p)
            for proc in procs:
                proc.join()
        else:
            process_packets(conf, reader.read_data())
        sleep(0.0001)


if __name__ == '__main__':
    main('config.json')


