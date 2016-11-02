import logging
from logging.handlers import RotatingFileHandler

http_formatter = logging.Formatter(
    "%(asctime)-15s - %(user)-10s - %(levelname)s %(message)s")
try:
    http_handler = RotatingFileHandler("pppoe_worker.log",
                                       maxBytes=1024 * 1024 * 100,
                                       backupCount=20)
except IOError:
    raise IOError("Cannot create log file")
http_handler.setLevel(logging.INFO)
http_handler.setFormatter(http_formatter)


def setupLog(logger, level=logging.INFO):
    logger.setLevel(level)
    logger.addHandler(http_handler)
    return logger


def getHandler():
    return http_handler
