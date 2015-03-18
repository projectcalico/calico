# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
openstack.test.test_plugin_etcd
~~~~~~~~~~~

Unit test for the Calico/OpenStack Plugin using etcd transport.
"""
import mock
import unittest

import calico.openstack.test.lib as lib
import calico.openstack.mech_calico as mech_calico


class TestPluginEtcd(lib.Lib, unittest.TestCase):

    def check_etcd_write(self, key, value):
        """Print each etcd write as it occurs.
        """
        print "etcd write: %s\n%s" % (key, value)

    def setUp(self):
        """Setup before each test case.
        """
        # Do common plugin test setup.
        super(TestPluginEtcd, self).setUp()

        # Hook the (mock) etcd client.
        self.client = lib.m_etcd.Client()
        self.client.write.side_effect = self.check_etcd_write

        # Prepare an empty read object.
        self.empty_read = mock.Mock()
        self.empty_read.children = []

    def test_start_no_ports(self):
        """Startup with no ports or existing etcd data.
        """
        # Arrange for etcd reads to return nothing.
        self.client.read.return_value = self.empty_read

        # Tell the driver to initialize.
        self.driver.initialize()
