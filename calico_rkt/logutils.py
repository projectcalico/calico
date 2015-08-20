#!/bin/python
import logging
import os

LOG_DIR = '/var/log/calico/rkt-plugin'

def configure_logger(logger, log_dir=None):
    if log_dir is None:
        log_dir = LOG_DIR

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    hdlr = logging.FileHandler(filename=log_dir+'/calico.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)