import inspect
import json
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path


class SingletonClass:
    __instance = None

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
            # Call pre-init method if the successor class has one
            if hasattr(cls, '_pre_init'):
                cls._pre_init(cls.__instance)
        return cls.__instance


class Logger(SingletonClass):
    """
    Universal singleton logging class. Could be transparently used instead of stdlib logging.
    """

    colors = {
        'warning': "\033[93m",
        'error': "\033[91m",
        'normal': "\033[0m"
    }

    logging_levels = {
        'CRITICAL': 50,
        'ERROR': 40,
        'WARNING': 30,
        'INFO': 20,
        'DEBUG': 10
    }

    @classmethod
    def _pre_init(cls, inst):
        inst.set_logger()

    def set_logger(self,
                   log_dir=None,
                   log_file=None,
                   json=None,
                   level=None,
                   stdout=True,
                   reflect=True,
                   size=10,
                   keep=10,
                   date_format='DMY'):
        self.level = level or 'INFO'
        self.jsonify = json
        self.reflect = reflect
        self.stdout = stdout
        self.date_format = date_format or 'DMY'
        self.logger = logging.getLogger('SuperLogger')
        self.logger.setLevel(Logger.logging_levels[self.level])
        self.logger.handlers.clear()

        if log_dir and not Path(log_dir).exists():
            try:
                Path(log_dir).mkdir()
            except Exception as e:
                print(e, 'Could not create log dir. Critical error, terminating...')
                exit()

        file_path = Path(log_dir, log_file) if log_dir and log_file else None

        if file_path:
            handler = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes=(size or 10) * 1048576,
                backupCount=keep or 10
            )
        else:
            handler = logging.handlers.SysLogHandler()

        handler.setLevel(self.logger.level)
        self.logger.addHandler(handler)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state

    def __getattr__(self, item: str):
        """
        For the stdlib logger compatibility we will pass request calling non-existent attr / method
        to the self.log method if it named after logging level.
        For the instance, we don't have the method 'debug', so will call self.log (thru the deco _level_deco)
        holding desired level in self._level_ prop.
        """
        if item.swapcase() in Logger.logging_levels:
            self._level_ = item
            return self._level_deco

    def _level_deco(self, *args, **kwargs):
        return self.log(*args, level=self._level_, **kwargs)

    def _get_ts(self):
        if self.jsonify:
            return datetime.now().timestamp()
        if self.date_format == 'DMY':
            return datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def _get_line(self,
                  *args,
                  **kwargs):

        try:
            log = {
                '_time': self._get_ts(),
                **kwargs,
                'record': ' '.join([str(n) for n in args if n])
            }
        except Exception as e:
            self.log(f'Wrong log call: {e}, {args}')
            return
        if self.jsonify:
            return json.dumps(log)

        return ' '.join(
            (
                str(n) for n in (
                log['_time'], log['level'], '-- PID', log['pid'],
                log['module'], log['function'], log['line'], '--', log['record'],
                ' '.join((f'{k} {v}' for k, v in kwargs.items())))
            )
        )

    def log(self, *args, level='info', **kwargs):
        """
        Call the log method to produce the record described by params

        :param args: The sequence of args that will be concatenated as a payload or inserted into json line as 'record'
        :param level: Keyword arg using to determine the log level of the record
        :param kwargs: The set of key:value that will be concatenated or inserted into json line
        :return: None
        """

        if self.logging_levels.get(level.upper(), 0) < self.logging_levels[self.level]:
            return

        log_units = {}

        if self.reflect:
            call_frame = inspect.getouterframes(inspect.currentframe(), 2)
            log_units.update(
                module=call_frame[1][1][call_frame[1][1].rfind('/') + 1:],  # Get the caller file name clearing the path
                line=str(call_frame[1][2]),
                func=call_frame[1][3]
            )

        log_units.update(
            pid=os.getpid()
        )

        log_line = self._get_line(
            *args,
            **log_units,
            **kwargs
        )

        print(
            Logger.colors.get(level, ''),
            log_line,
            Logger.colors['normal']
        ) if self.stdout else None

        # Calling the level method of the self.logger,
        # ex. log('msg', level='info') will turn into self.logger.info('msg')
        if hasattr(self.logger, level):
            getattr(self.logger, level)(log_line)


logger = Logger()
