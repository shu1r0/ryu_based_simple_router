from logging import getLogger, Logger, DEBUG, StreamHandler, Formatter, handlers, setLoggerClass
import datetime


def get_logger(name, filename="simple_router.log"):
    if name.find("of_simple_router.") == -1:
        name = "of_simple_router."+name
    setLoggerClass(Logger)
    logger = getLogger(name)
    logger.setLevel(DEBUG)

    formatter = Formatter("%(asctime)s | %(process)d | %(name)s, %(lineno)d | %(levelname)s | %(message)s")

    # stream_handler = StreamHandler()
    # stream_handler.setLevel(DEBUG)
    # stream_handler.setFormatter(formatter)
    # logger.addHandler(stream_handler)

    file_handler = handlers.RotatingFileHandler(filename="log/" + filename,
                                                maxBytes=16777216,)
    file_handler.setLevel(DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger