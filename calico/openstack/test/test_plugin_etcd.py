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

    def check_etcd_delete(self, key):
        """Print each etcd delete as it occurs."""
        print "etcd delete: %s" % key
        del self.etcd_data[key]
        self.recent_deletes.add(key)

    def assertEtcdWrites(self, expected):
        self.assertEqual(self.recent_writes, expected)
        self.recent_writes = {}

    def assertEtcdDeletes(self, expected):
        self.assertEqual(self.recent_deletes, expected)
        self.recent_deletes = set()

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

        # Print and return the result object.
        print "etcd read: %s\nvalue: %s" % (key, read_result.value)

        if recursive:
            # Also see if this key has any children, and read those.
            read_result.children = []
            keylen = len(key) + 1
            for k in self.etcd_data.keys():
                if k[:keylen] == key + '/':
                    child = mock.Mock()
                    child.key = k
                    child.value = self.etcd_data[k]
                    read_result.children.append(child)
            print "children: %s" % [child.key
                                    for child in read_result.children]
        else:
            read_result.children = None

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
        self.client.read.side_effect = self.etcd_read
        self.client.write.side_effect = self.check_etcd_write
        self.client.delete.side_effect = self.check_etcd_delete

        # Start with an empty etcd database.
        self.etcd_data = {}

        # Start with an empty set of recent writes and deletes.
        self.recent_writes = {}
        self.recent_deletes = set()

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
        self.assertEtcdDeletes(set())

        # Delete lib.port1
        context = mock.Mock()
        context._port = lib.port1
        self.driver.delete_port_postcommit(context)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set(['/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678']))
        self.osdb_ports = [lib.port2]

        # Do another resync - expect no changes to the etcd data.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Add lib.port1 back again.
        self.driver.create_port_postcommit(context)
        expected_writes = {
            '/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
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
        self.assertEtcdDeletes(set())
        self.check_update_port_status_called(context)
        self.osdb_ports = [lib.port1, lib.port2]

        # Migrate port1 to a different host.
        context._port = lib.port1.copy()
        context._port['binding:host_id'] = 'new-host'
        context.original = lib.port1
        self.driver.update_port_postcommit(context)
        del expected_writes['/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678']
        expected_writes['/calico/host/new-host/workload/openstack/endpoint/DEADBEEF-1234-5678'] = {
            "name": "tapDEADBEEF-12",
            "profile_id": "SGID-default",
            "mac": "00:11:22:33:44:55",
            "ipv4_gateway": "10.65.0.1",
            "ipv4_nets": ["10.65.0.2/32"],
            "state": "active",
            "ipv6_nets": []
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678']))

        # Now resync again without updating self.osdb_ports to reflect that
        # port1 has moved to new-host.  The effect will be as though we've
        # missed a further update that moved port1 back to felix-host-1; this
        # resync will now discover that.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        expected_writes = {
            '/calico/host/felix-host-1/workload/openstack/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []}
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/host/new-host/workload/openstack/endpoint/DEADBEEF-1234-5678']))
