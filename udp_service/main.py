from time import sleep

from data_parser import BasicParser
from data_reader import DataReader
from data_writer import DataWriter
from logger import logger
from config import import_config


def main(config_file):
    conf = import_config(config_file)
    logger.set_logger(
        **conf.get('logging')
    )
    logger.log("Logger inited.")
    parser = BasicParser(
        logger,
        sensors=conf.get('sensors'),
        pattern=conf.get('pattern')
    )
    reader = DataReader(
        logger,
        base_dir=conf.get('paths', {}).get('rawpath'),
        file_size=1000000,
        delete_files=True
    )
    writer = DataWriter(
        logger,
        base_dir=conf.get('paths', {}).get('jsonpath'),
        batch_length=10000
    )

    while 1:
        packets = reader.read_data()

        for packet in packets:
            data = parser.parse_packet(packet)
            writer.write_line(data)

        sleep(0.0001)


if __name__ == '__main__':
    main('config.json')


