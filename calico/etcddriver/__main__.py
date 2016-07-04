# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
#
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
calico.etcddriver.__main__
~~~~~~~~~~~~~~~~~~~~~~~~~~

Main entry point for the etcd driver, responsible for basic logging config
and starting our threads.
"""

import logging
import os
import socket
import sys

from calico.etcddriver import driver
from calico import common

_log = logging.getLogger(__name__)


def main():
    """etcd driver main entry point.

    Implementation note: this is implemented as a function to allow
    it to be imported and executed from the pyinstaller launcher.

    Without the extra indirection, pyilauncher would deadlock when
    it tried to import this module.
    """
    last_ppid = os.getppid()
    common.default_logging(gevent_in_use=False,
                           syslog_executable_name="calico-felix-etcd")
    felix_sck = socket.socket(socket.AF_UNIX,
                              socket.SOCK_STREAM)
    try:
        felix_sck.connect(sys.argv[1])
    except:
        _log.exception("Failed to connect to Felix")
        raise
    etcd_driver = driver.EtcdDriver(felix_sck)
    etcd_driver.start()
    while not etcd_driver.join(timeout=1):
        parent_pid = os.getppid()
        # Defensive, just in case we don't get a socket error, check if the
        # parent PID has changed, indicating that Felix has died.
        if parent_pid == 1 or parent_pid != last_ppid:
            _log.critical("Process adopted, assuming felix has died")
            etcd_driver.stop()
            break
    _log.critical("Driver shutting down.")


if __name__ == "__main__":
    main()  # pragma: no cover
