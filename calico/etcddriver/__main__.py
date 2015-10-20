# -*- coding: utf-8 -*-

# Copyright (c) 2014, 2015 Metaswitch Networks
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
import socket
import sys

from calico.etcddriver.driver import EtcdDriver
from calico.common import default_logging

_log = logging.getLogger(__name__)

default_logging(gevent_in_use=False)

felix_sck = socket.socket(socket.AF_UNIX,
                          socket.SOCK_STREAM)
try:
    felix_sck.connect(sys.argv[1])
except:
    _log.exception("Failed to connect to Felix")
    raise

driver = EtcdDriver(felix_sck)
driver.start()
driver.join()
