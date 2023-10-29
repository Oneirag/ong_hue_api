import logging
import logging.handlers
import os
from functools import partial

from win11toast import notify

from ong_hue_api import name


class NotificationHandler(logging.Handler):
    """Emits notifications as bubble in windows"""

    def __init__(self) -> None:
        logging.Handler.__init__(self=self)

    def emit(self, record) -> None:
        notify(record.msg, duration="short")


def create_logger(log_path=None, level=logging.DEBUG) -> logging.Logger:
    """Creates a logger with files in the given path (or current path) and returns it"""
    path = log_path or os.getcwd()
    log_filename = os.path.join(path, f"hue_api_{name}.log")
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        for handler_class in logging.StreamHandler, partial(logging.handlers.TimedRotatingFileHandler,
                                                            filename=log_filename, when="D", backupCount=5):
            # create handler and set level to debug
            # ch = logging.StreamHandler()
            handler = handler_class()
            handler.setLevel(logging.DEBUG)
            # create formatter
            """
            %(pathname)s Full pathname of the source file where the logging call was issued(if available).

            %(filename)s Filename portion of pathname.
            
            %(module)s Module (name portion of filename).
            
            %(funcName)s Name of function containing the logging call.
            
            %(lineno)d Source line number where the logging call was issued (if available).
            """
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - '
                                          '{%(filename)s:%(lineno)d} - %(message)s')
            # add formatter to handler
            handler.setFormatter(formatter)
            # add handler to logger
            logger.addHandler(handler)
    return logger


if __name__ == '__main__':
    logger = create_logger()
    logger.debug("Hola")
    logger.info("que tal")
    log2 = create_logger()
    log2.info("Sales?")
