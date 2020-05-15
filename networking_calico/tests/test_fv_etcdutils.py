# -*- coding: utf-8 -*-
# Copyright (c) 2020 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
test_fv_etcdutils
~~~~~~~~~~~~~~

Tests for etcdutils with a real etcd server.
"""

from __future__ import print_function

import logging
import os
import unittest

import eventlet
eventlet.monkey_patch()

from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico import etcdutils

_log = logging.getLogger(__name__)


class TestFVEtcdutils(unittest.TestCase):
    def setUp(self):
        super(TestFVEtcdutils, self).setUp()

    def tearDown(self):
        self.stop_etcd_server()
        super(TestFVEtcdutils, self).tearDown()

    def start_etcd_server(self):
        os.system("docker run -d --rm --net=host --name etcd" +
                  " quay.io/coreos/etcd:v3.3.11 etcd" +
                  " --advertise-client-urls http://127.0.0.1:2379" +
                  " --listen-client-urls http://0.0.0.0:2379")

    def stop_etcd_server(self):
        os.system("docker kill etcd")

    def test_restart_resilience(self):
        # Start a real local etcd server.
        self.start_etcd_server()

        # Set up minimal config, so EtcdWatcher will use that etcd.
        calico_config.register_options(cfg.CONF)

        # Create and start an EtcdWatcher.
        ew = etcdutils.EtcdWatcher('/calico/felix/v2/abc/host',
                                   '/round-trip-check')
        debug_msgs = []
        ew.debug_reporter = lambda msg: debug_msgs.append(msg)
        eventlet.spawn(ew.start)

        # Let it run for 10 seconds normally.
        eventlet.sleep(10)

        # Stop the etcd server.
        debug_msgs.append("Stopping etcd server")
        self.stop_etcd_server()

        # Let it run for 10 seconds more.
        eventlet.sleep(10)

        # Restart the etcd server.
        debug_msgs.append("Restarting etcd server")
        self.start_etcd_server()

        # Let it run for 10 seconds more.
        eventlet.sleep(10)

        # Stop the EtcdWatcher.
        debug_msgs.append("Stopping EtcdWatcher")
        ew.stop()

        # Find the message for "Restarting etcd server" and count
        # "Write round-trip key" messages before and after that.  Both
        # counts should be non-zero if the EtcdWatcher is working
        # correctly before and after the etcd server restart.
        num_key_writes_before_restart = 0
        num_key_writes_after_restart = 0
        seen_restart_msg = False
        for msg in debug_msgs:
            if msg == "Restarting etcd server":
                seen_restart_msg = True
            if msg == "Write round-trip key":
                if seen_restart_msg:
                    num_key_writes_after_restart += 1
                else:
                    num_key_writes_before_restart += 1
        self.assertGreater(
            num_key_writes_before_restart,
            0,
            msg="No round-trip key writes before restart: %r" % debug_msgs,
        )
        self.assertGreater(
            num_key_writes_after_restart,
            0,
            msg="No round-trip key writes after restart: %r" % debug_msgs,
        )

        # Kill the etcd server.
        self.stop_etcd_server()
