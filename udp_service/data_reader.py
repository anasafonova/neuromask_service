from pathlib import Path


class DataReader:

    def __init__(self, logger, base_dir: str, delete_files=True):
        self.logger = logger
        self.base_dir = Path(base_dir)
        self.delete_files = delete_files


