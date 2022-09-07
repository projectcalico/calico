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
import shutil
import subprocess
import unittest

import eventlet
eventlet.monkey_patch()

from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico import etcdutils
from networking_calico import etcdv3

_log = logging.getLogger(__name__)


class TestFVEtcdutils(unittest.TestCase):
    def setUp(self):
        super(TestFVEtcdutils, self).setUp()
        self.etcd_server_running = False

    def tearDown(self):
        self.stop_etcd_server()
        etcdv3._client = None
        super(TestFVEtcdutils, self).tearDown()

    def start_etcd_server(self):
        shutil.rmtree(".default.etcd", ignore_errors=True)
        self.etcd = subprocess.Popen([
            "/usr/local/bin/etcd",
            "--advertise-client-urls", "http://127.0.0.1:2379",
            "--listen-client-urls", "http://0.0.0.0:2379"
        ])
        self.etcd_server_running = True

    def wait_etcd_ready(self):
        self.assertTrue(self.etcd_server_running)
        ready = False
        for ii in range(10):
            try:
                _log.warning("Try connecting to etcd server...")
                etcdv3.get_status()
                ready = True
                break
            except Exception:
                _log.exception("etcd server not ready yet")
                eventlet.sleep(2)
        self.assertTrue(ready)

    def stop_etcd_server(self):
        if self.etcd_server_running:
            self.etcd.kill()
            self.etcd.wait()
        self.etcd_server_running = False

    def test_must_update(self):
        # Start a real local etcd server.
        self.start_etcd_server()

        # Set up minimal config, so EtcdWatcher will use that etcd.
        calico_config.register_options(cfg.CONF)

        # Ensure etcd server is ready.
        self.wait_etcd_ready()

        # Try a put with MUST_UPDATE; should fail as does not yet exist.
        succeeded = etcdv3.put("/testkey", "testvalue", mod_revision=etcdv3.MUST_UPDATE)
        self.assertFalse(succeeded)

        # Try a put with mod_revision 0, i.e. must create.
        succeeded = etcdv3.put("/testkey", "testvalue", mod_revision=0)
        self.assertTrue(succeeded)

        # Try again with MUST_UPDATE; should now succeed.
        succeeded = etcdv3.put("/testkey", "testvalue2", mod_revision=etcdv3.MUST_UPDATE)
        self.assertTrue(succeeded)

        # Try again with mod_revision 0; should now fail.
        succeeded = etcdv3.put("/testkey", "testvalue2", mod_revision=0)
        self.assertFalse(succeeded)

        # Kill the etcd server.
        self.stop_etcd_server()

    def test_restart_resilience_2s(self):
        self._test_restart_resilience(2)

    def test_restart_resilience_5s(self):
        self._test_restart_resilience(5)

    def test_restart_resilience_15s(self):
        self._test_restart_resilience(15)

    def _test_restart_resilience(self, restart_interval_secs):
        # Start a real local etcd server.
        self.start_etcd_server()

        # Set up minimal config, so EtcdWatcher will use that etcd.
        calico_config.register_options(cfg.CONF)

        # Ensure etcd server is ready.
        self.wait_etcd_ready()

        # Create and start an EtcdWatcher.
        ew = etcdutils.EtcdWatcher('/calico/felix/v2/abc/host',
                                   '/round-trip-check')
        debug_msgs = []
        ew.debug_reporter = lambda msg: debug_msgs.append(msg)
        eventlet.spawn(ew.start)

        # Let it run for 5 seconds normally.  The EtcdWatcher writes a
        # round-trip-check key every 3.3s (WATCH_TIMEOUT_SECS / 3), so
        # 5s is enough for at least one of those writes.
        eventlet.sleep(5)

        # Stop the etcd server.
        debug_msgs.append("Stopping etcd server")
        self.stop_etcd_server()

        # Wait for the specified restart interval.
        eventlet.sleep(restart_interval_secs)

        # Restart the etcd server.
        debug_msgs.append("Restarting etcd server")
        self.start_etcd_server()

        # Ensure etcd server is ready.
        self.wait_etcd_ready()

        # Let it run for 5 seconds more.  As above, this should be
        # enough for at least one round-trip-check key write.
        eventlet.sleep(5)

        # Stop the EtcdWatcher.
        debug_msgs.append("Stopping EtcdWatcher")
        ew.stop()

        # Find the message for "Restarting etcd server" and count
        # "Wrote round-trip key" messages before and after that.  Both
        # counts should be non-zero if the EtcdWatcher is working
        # correctly before and after the etcd server restart.
        num_key_writes_before_restart = 0
        num_key_writes_after_restart = 0
        seen_restart_msg = False
        for msg in debug_msgs:
            if msg == "Restarting etcd server":
                seen_restart_msg = True
            if msg == "Wrote round-trip key":
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
