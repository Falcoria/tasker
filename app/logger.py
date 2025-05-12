import logging

from enum import Enum

from app.config import config


class LogLevel(Enum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class Logger:
    def __init__(self, name, logger_level: LogLevel):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logger_level.value)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def get_logger(self):
        return self.logger


logger = Logger(config.logger_name, LogLevel[config.logger_level.upper()]).get_logger()