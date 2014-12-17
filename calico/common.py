# -*- coding: utf-8 -*-

# Copyright (c) 2014 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
calico.common
~~~~~~~~~~~~

Calico common utilities.
"""
import logging
import logging.handlers
import os
import re
import sys
import errno

# Various useful regular expressions.
IPV4_REGEX = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_REGEX = re.compile("^[a-f0-9]+:[:a-f0-9]+$")
PORT_REGEX = re.compile("^(([0-9]+)|([0-9]+-[0-9]+))$")
INT_REGEX  = re.compile("^[0-9]+$")


AGENT_TYPE_CALICO = 'Calico agent'
FORMAT_STRING = '%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s'

def mkdir_p(path):
    """http://stackoverflow.com/a/600612/190597 (tzot)"""
    try:
        os.makedirs(path, exist_ok=True)  # Python>3.2
    except TypeError:
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise


def default_logging():
    """
    Sets up the Calico default logging, with default severities.

    Our default logging consists of:

    - setting the log level of the root logger to DEBUG (a safe initial value)
    - attaching a SysLog handler with no formatter (log to syslog), ERROR level
      only
    - attaching a StreamHandler with the Calico formatter, to log to stdout,
      with DEBUG level

    This default explicitly excludes adding logging to file. This is because
    working out what file to log to requires reading the configuration file,
    and doing that may cause errors that we want to log! To add a file logger,
    call :meth:`complete_logging() <calico.common.complete_logging>` after
    this function has been called.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setLevel(logging.ERROR)
    root_logger.addHandler(syslog_handler)

    formatter = logging.Formatter(FORMAT_STRING)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)


def complete_logging(logfile=None,
                     file_level=logging.DEBUG,
                     syslog_level=logging.ERROR,
                     stream_level=logging.DEBUG):
    """
    Updates the logging configuration based on learned configuration.

    The purpose of this function is to update the previously set logging
    configuration such that we can start logging to file. This is done in a
    separate step to the initial logging configuration in order to ensure that
    logging is available as early in execution as possible, i.e. before the
    config file has been parsed.

    This function must only be called once, after 
    :meth:`default_logging() <calico.common.default_logging>`
    has been called.
    """
    root_logger = logging.getLogger()

    # If default_logging got called already, we'll have some loggers in place.
    # Update their levels.
    for handler in root_logger.handlers:
        if isinstance(handler, logging.handlers.SysLogHandler):
            handler.setLevel(syslog_level)
        elif isinstance(handler, logging.StreamHandler):
            handler.setLevel(stream_level)

    # If we've been given a log file, log to file as well.
    if logfile is not None:
        mkdir_p(os.path.dirname(logfile))

        formatter = logging.Formatter(FORMAT_STRING)
        file_handler = logging.handlers.TimedRotatingFileHandler(
            logfile, when="D", backupCount=10
        )
        file_handler.setLevel(file_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
