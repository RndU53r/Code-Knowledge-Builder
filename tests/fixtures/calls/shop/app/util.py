import logging


def log_call(fn):
    return fn


def audit(item):
    logging.info("audit %s", item)


def notify(callback, item):
    return callback(item)
