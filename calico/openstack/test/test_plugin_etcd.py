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
import eventlet
import json
import mock
import unittest

import calico.openstack.test.lib as lib
import calico.openstack.mech_calico as mech_calico
import calico.openstack.t_etcd as t_etcd


class TestPluginEtcd(lib.Lib, unittest.TestCase):

    def check_etcd_write(self, key, value):
        """Print each etcd write as it occurs, and save into the accumulated etcd
        database.
        """
        print "etcd write: %s\n%s" % (key, value)
        self.etcd_data[key] = value
        self.recent_writes[key] = json.loads(value)

    def assertEtcdWrites(self, expected):
        self.assertEqual(self.recent_writes, expected)
        self.recent_writes = {}

    def etcd_read(self, key, recursive=False):
        """Read from the accumulated etcd database.
        """
        # Prepare a read result object.
        read_result = mock.Mock()
        read_result.key = key

        # Set the object's value - i.e. the value, if any, of exactly the
        # specified key.
        if key in self.etcd_data:
            read_result.value = self.etcd_data[key]
        else:
            read_result.value = None

        if recursive:
            # Also see if this key has any children, and read those.
            child_keys = set()
            keylen = len(key) + 1
            for k in self.etcd_data.keys():
                if k[:keylen] == key + '/':
                    child_keys.add(key + '/' + k[keylen:].split('/')[0])
            read_result.children = [self.etcd_read(child_key, True)
                                    for child_key in child_keys]

        # Print and return the result object.
        print "etcd read: %s\n%s\n%s" % (key,
                                         read_result.value,
                                         read_result.children)
        return read_result

    def setUp(self):
        """Setup before each test case.
        """
        # Do common plugin test setup.
        super(TestPluginEtcd, self).setUp()

        # Use etcd transport instead of 0MQ.
        self.driver.transport = t_etcd.CalicoTransportEtcd(self.driver,
                                                           mech_calico.LOG)

        # Hook the (mock) etcd client.
        self.client = lib.m_etcd.Client()
        self.client.write.side_effect = self.check_etcd_write
        self.client.read.side_effect = self.etcd_read

        # Start with an empty etcd database.
        self.etcd_data = {}

        # Start with an empty set of recent writes.
        self.recent_writes = {}

    def test_start_no_ports(self):
        """Startup with no ports or existing etcd data.
        """
        # Tell the driver to initialize.
        self.driver.initialize()

        # Allow the etcd transport's resync thread to run.
        self.give_way()
        self.simulated_time_advance(1)
        self.assertEtcdWrites({})

    def test_start_two_ports(self):
        """Startup with two existing ports but no existing etcd data.
        """
        # Provide two Neutron ports.
        self.osdb_ports = [lib.port1, lib.port2]

        # Tell the driver to initialize.
        self.driver.initialize()

        # Allow the etcd transport's resync thread to run.
        self.give_way()
        self.simulated_time_advance(1)
        expected_writes = {
            '/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/host/felix-host-1/workload/openstack/endpoint/FACEBEEF-1234-5678':
                {"name": "tapFACEBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:66",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.3/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/policy/profile/SGID-default/rules':
                {"outbound_rules": [{"dst_ports": ["1:65535"],
                                     "protocol": -1,
                                     "dst_tag": None,
                                     "dst_net": "0.0.0.0/0"},
                                    {"dst_ports": ["1:65535"],
                                     "protocol": -1,
                                     "dst_tag": None,
                                     "dst_net": "::/0"}],
                 "inbound_rules": [{"src_ports": ["1:65535"],
                                    "src_net": None,
                                    "protocol": -1,
                                    "src_tag": "SGID-default"},
                                   {"src_ports": ["1:65535"],
                                    "src_net": None,
                                    "protocol": -1,
                                    "src_tag": "SGID-default"}]},
            '/calico/policy/profile/SGID-default/tags':
                ["SGID-default"]
        }
        self.assertEtcdWrites(expected_writes)

        # Allow it to run again, this time auditing against the etcd data that
        # was written on the first iteration.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
