from pathlib import Path
from datetime import datetime
from json import dumps


class DataWriter:

    def __init__(self, logger, base_dir: str, batch_length=1000):
        self.logger = logger
        self.base_dir = Path(base_dir)
        if not self.base_dir.exists():
            self._create_base_dir(self.base_dir)
        self.batch_length = batch_length

        self._current_file_name = None
        self._lines_count = 0

    def _create_base_dir(self, _dir: Path):
        try:
            Path.mkdir(_dir)
        except:
            self.logger.error(f"Unable to create dir: {self.base_dir}")

    @staticmethod
    def _get_new_file_name():
        return f"{str(datetime.utcnow().timestamp())}.json"

    @property
    def _file(self):
        if not self._current_file_name or self._lines_count >= self.batch_length:
            self._current_file_name = self._get_new_file_name()
            self._lines_count = 0

        return Path(self.base_dir, self._current_file_name)

    def write_line(self, data: dict):
        with open(self._file, "a") as f:
            f.write(
                dumps(data) + "/n"
            )
        self._lines_count += 1

    def write_lines(self, data: list):
        for line in data:
            self.write_line(line)


