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
import copy
import eventlet
import json
import mock
import unittest
from calico import common
from calico.datamodel_v1 import FELIX_STATUS_DIR

import calico.openstack.test.lib as lib
import calico.openstack.mech_calico as mech_calico
import calico.openstack.t_etcd as t_etcd
from socket import timeout as SocketTimeout
from urllib3.exceptions import ReadTimeoutError


class EtcdException(Exception):
    pass


class EtcdKeyNotFound(EtcdException):
    pass


class EtcdClusterIdChanged(EtcdException):
    pass


class EtcdEventIndexCleared(EtcdException):
    pass


lib.m_etcd.EtcdException = EtcdException
lib.m_etcd.EtcdKeyNotFound = EtcdKeyNotFound
lib.m_etcd.EtcdClusterIdChanged = EtcdClusterIdChanged
lib.m_etcd.EtcdEventIndexCleared = EtcdEventIndexCleared


class TestPluginEtcd(lib.Lib, unittest.TestCase):

    def maybe_reset_etcd(self):
        if self.reset_etcd_after is not None:
            self.reset_etcd_after -= 1
            if self.reset_etcd_after == 0:
                self.etcd_data = {}
                self.reset_etcd_after = None
                print "etcd reset"
                self.assert_etcd_writes_deletes = False

    def check_etcd_write(self, key, value, **kwargs):
        """Print each etcd write as it occurs, and save into the accumulated etcd
        database.
        """
        self.maybe_reset_etcd()

        # Confirm that, if prevIndex is provided, its value is not None.
        self.assertTrue(kwargs.get('prevIndex', 0) is not None)

        print "etcd write: %s\n%s" % (key, value)
        self.etcd_data[key] = value
        try:
            self.recent_writes[key] = json.loads(value)
        except ValueError:
            self.recent_writes[key] = value

    def check_etcd_delete(self, key, **kwargs):
        """Print each etcd delete as it occurs."""
        self.maybe_reset_etcd()
        print "etcd delete: %s" % key
        if kwargs.get('recursive', False):
            keylen = len(key) + 1
            for k in self.etcd_data.keys():
                if k == key or k[:keylen] == key + '/':
                    del self.etcd_data[k]
            self.recent_deletes.add(key + '(recursive)')
        else:
            try:
                del self.etcd_data[key]
            except KeyError:
                raise EtcdKeyNotFound()
            self.recent_deletes.add(key)

    def assertEtcdWrites(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(self.recent_writes, expected)
        self.recent_writes = {}

    def assertEtcdDeletes(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(self.recent_deletes, expected)
        self.recent_deletes = set()

    def etcd_read(self, key, wait=False, waitIndex=None, recursive=False, timeout=None):
        """
        Read from the accumulated etcd database.
        """
        self.maybe_reset_etcd()

        # Slow down reading from etcd status subtree to allow threads to run more often
        if wait and key == FELIX_STATUS_DIR:
            eventlet.sleep(30)
            self.driver.db.create_or_update_agent = mock.Mock()

        self.etcd_data[FELIX_STATUS_DIR + "/vm1/status"] = {"time": "2015-08-14T10:37:54"}

        # Prepare a read result object.
        read_result = mock.Mock()
        read_result.modifiedIndex = 123
        read_result.key = key
        read_result.etcd_index = 0

        # Set the object's value - i.e. the value, if any, of exactly the
        # specified key.
        if key in self.etcd_data:
            read_result.value = self.etcd_data[key]
        else:
            read_result.value = None
            if not recursive:
                raise lib.m_etcd.EtcdKeyNotFound()

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
            if read_result.value is None and read_result.children == []:
                raise lib.m_etcd.EtcdKeyNotFound(self.etcd_data)
            # Actual direct children of the dir in etcd response.
            # Needed for status_dir, where children are dirs and
            # needs to be iterated.
            read_result._children = []
            list_of_statuses = [{"key": K} for K in self.etcd_data.keys()]
            read_result._children.append({"nodes": list_of_statuses})
        else:
            read_result.children = None

        return read_result

    def setUp(self):
        """Setup before each test case.
        """
        # Start with an empty etcd database.
        self.etcd_data = {}

        # Do common plugin test setup.
        super(TestPluginEtcd, self).setUp()

        # Hook the (mock) etcd client.
        self.client = lib.m_etcd.Client()
        self.client.read.side_effect = self.etcd_read
        self.client.write.side_effect = self.check_etcd_write
        self.client.delete.side_effect = self.check_etcd_delete

        # Start with an empty set of recent writes and deletes.
        self.recent_writes = {}
        self.recent_deletes = set()

        # Reset the counter for when we'll reset the etcd database.
        self.reset_etcd_after = None
        self.assert_etcd_writes_deletes = True

    def test_start_no_ports(self):
        """Startup with no ports or existing etcd data.
        """
        # Allow the etcd transport's resync thread to run. The last thing it
        # does is write the Felix config, so let it run three reads.
        self.give_way()
        self.simulated_time_advance(31)
        self.assertEtcdWrites(
            {'/calico/v1/config/InterfacePrefix': 'tap',
             '/calico/v1/Ready': True,
            '/calico/v1/policy/profile/SGID-default/rules':
                {"outbound_rules": [{"dst_ports": ["1:65535"],
                                     "dst_net": "0.0.0.0/0",
                                     "ip_version": 4},
                                    {"dst_ports": ["1:65535"],
                                     "dst_net": "::/0",
                                     "ip_version": 6}],
                 "inbound_rules": [{"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4},
                                   {"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 6}]},
            '/calico/v1/policy/profile/SGID-default/tags':
                ["SGID-default"]
        })

    def test_etcd_reset(self):
        for n in range(1, 20):
            print "\nReset etcd data after %s reads/writes/deletes\n" % n
            self.reset_etcd_after = n
            self.test_start_two_ports()
            self.etcd_data = {}

    def test_start_two_ports(self):
        """Startup with two existing ports but no existing etcd data.
        """
        # Provide two Neutron ports.
        self.osdb_ports = [lib.port1, lib.port2]

        # Allow the etcd transport's resync thread to run.
        self.give_way()
        self.simulated_time_advance(31)
        expected_writes = {
            '/calico/v1/config/InterfacePrefix': 'tap',
            '/calico/v1/Ready': True,
            '/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_ids": ["SGID-default"],
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/v1/host/felix-host-1/workload/openstack/instance-2/endpoint/FACEBEEF-1234-5678':
                {"name": "tapFACEBEEF-12",
                 "profile_ids": ["SGID-default"],
                 "mac": "00:11:22:33:44:66",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.3/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/v1/policy/profile/SGID-default/rules':
                {"outbound_rules": [{"dst_ports": ["1:65535"],
                                     "dst_net": "0.0.0.0/0",
                                     "ip_version": 4},
                                    {"dst_ports": ["1:65535"],
                                     "dst_net": "::/0",
                                     "ip_version": 6}],
                 "inbound_rules": [{"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4},
                                   {"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 6}]},
            '/calico/v1/policy/profile/SGID-default/tags':
                ["SGID-default"]
        }
        self.assertEtcdWrites(expected_writes)

        # Allow it to run again, this time auditing against the etcd data that
        # was written on the first iteration.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Delete lib.port1.
        context = mock.MagicMock()
        context._port = lib.port1
        context._plugin_context.session.query.return_value.filter_by.side_effect = (
            self.ips_for_port
        )
        self.driver.delete_port_postcommit(context)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set(['/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678']))
        self.osdb_ports = [lib.port2]

        # Do another resync - expect no changes to the etcd data.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Add lib.port1 back again.
        self.osdb_ports = [lib.port1, lib.port2]
        self.driver.create_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_ids": ["SGID-default"],
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/v1/policy/profile/SGID-default/rules':
                {"outbound_rules": [{"dst_ports": ["1:65535"],
                                     "dst_net": "0.0.0.0/0",
                                     "ip_version": 4},
                                    {"dst_ports": ["1:65535"],
                                     "dst_net": "::/0",
                                     "ip_version": 6}],
                 "inbound_rules": [{"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4},
                                   {"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 6}]},
            '/calico/v1/policy/profile/SGID-default/tags':
                ["SGID-default"]
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())
        self.check_update_port_status_called(context)

        # Migrate port1 to a different host.
        context._port = lib.port1.copy()
        context.original = lib.port1.copy()
        context._port['binding:host_id'] = 'new-host'
        self.osdb_ports[0]['binding:host_id'] = 'new-host'
        self.driver.update_port_postcommit(context)
        del expected_writes['/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678']
        expected_writes['/calico/v1/host/new-host/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678'] = {
            "name": "tapDEADBEEF-12",
            "profile_ids": ["SGID-default"],
            "mac": "00:11:22:33:44:55",
            "ipv4_gateway": "10.65.0.1",
            "ipv4_nets": ["10.65.0.2/32"],
            "state": "active",
            "ipv6_nets": []
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678']))
        self.check_update_port_status_called(context)

        # Now resync again, moving self.osdb_ports to move port 1 back to the
        # old host felix-host-1.  The effect will be as though we've
        # missed a further update that moved port1 back to felix-host-1; this
        # resync will now discover that.
        print "\nResync with existing etcd data\n"
        self.osdb_ports[0]['binding:host_id'] = 'felix-host-1'
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        expected_writes = {
            '/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_ids": ["SGID-default"],
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []}
        }

        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/v1/host/new-host/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678']))

        # Add another port with an IPv6 address.
        context._port = copy.deepcopy(lib.port3)
        self.osdb_ports.append(context._port)
        self.driver.create_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-2/workload/openstack/instance-3/endpoint/HELLO-1234-5678':
                {"name": "tapHELLO-1234-",
                 "profile_ids": ["SGID-default"],
                 "mac": "00:11:22:33:44:66",
                 "ipv6_gateway": "2001:db8:a41:2::1",
                 "ipv6_nets": ["2001:db8:a41:2::12/128"],
                 "state": "active",
                 "ipv4_nets": []},
            '/calico/v1/policy/profile/SGID-default/rules':
                {"outbound_rules": [{"dst_ports": ["1:65535"],
                                     "dst_net": "0.0.0.0/0",
                                     "ip_version": 4},
                                    {"dst_ports": ["1:65535"],
                                     "dst_net": "::/0",
                                     "ip_version": 6}],
                 "inbound_rules": [{"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4},
                                   {"dst_ports": ["1:65535"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 6}]},
            '/calico/v1/policy/profile/SGID-default/tags':
                ["SGID-default"]
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())
        self.check_update_port_status_called(context)
        self.osdb_ports = [lib.port1, lib.port2, context._port]

        # Create a new security group.
        # Update what the DB's queries should now return.
        self.db.get_security_groups.return_value = [
            {'id': 'SGID-default',
             'security_group_rules': [
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv4',
                  'port_range_min': -1},
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv6',
                  'port_range_min': -1},
                 {'remote_group_id': None,
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'egress',
                  'ethertype': 'IPv4',
                  'port_range_min': -1},
                 {'remote_group_id': None,
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'egress',
                  'ethertype': 'IPv6',
                  'port_range_min': -1}
             ]},
            {'id': 'SG-1',
             'security_group_rules': [
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv4',
                  'port_range_min': 5060,
                  'port_range_max': 5061}
             ]}
        ]
        self.db.get_security_group_rules.return_value = [
             {'remote_group_id': 'SGID-default',
              'remote_ip_prefix': None,
              'protocol': -1,
              'direction': 'ingress',
              'ethertype': 'IPv4',
              'security_group_id': 'SGID-default',
              'port_range_min': -1},
             {'remote_group_id': 'SGID-default',
              'remote_ip_prefix': None,
              'protocol': -1,
              'direction': 'ingress',
              'ethertype': 'IPv6',
              'security_group_id': 'SGID-default',
              'port_range_min': -1},
             {'remote_group_id': None,
              'remote_ip_prefix': None,
              'protocol': -1,
              'direction': 'egress',
              'ethertype': 'IPv4',
              'security_group_id': 'SGID-default',
              'port_range_min': -1},
             {'remote_group_id': None,
              'remote_ip_prefix': None,
              'protocol': -1,
              'direction': 'egress',
              'security_group_id': 'SGID-default',
              'ethertype': 'IPv6',
              'port_range_min': -1},
             {'remote_group_id': 'SGID-default',
              'remote_ip_prefix': None,
              'protocol': -1,
              'direction': 'ingress',
              'ethertype': 'IPv4',
              'security_group_id': 'SG-1',
              'port_range_min': 5060,
              'port_range_max': 5061}
        ]

        # Then, send in an update.
        self.notify_security_group_update(
            'SG-1',
            [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}
            ],
            None,
            'rule'
        )
        self.assertEtcdWrites({
            '/calico/v1/policy/profile/SG-1/rules':
                {"outbound_rules": [],
                 "inbound_rules": [{"dst_ports": ["5060:5061"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4}]},
            '/calico/v1/policy/profile/SG-1/tags':
                ["SG-1"]
        })

        # Now change the security group for that port.
        context.original = copy.deepcopy(context._port)
        context.original['security_groups'] = ['SGID-default']
        context._port['security_groups'] = ['SG-1']
        self.port_security_group_bindings.pop(2)
        self.port_security_group_bindings.append({
            'port_id': 'HELLO-1234-5678', 'security_group_id': 'SG-1'
        })
        self.driver.update_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-2/workload/openstack/instance-3/endpoint/HELLO-1234-5678':
                {"name": "tapHELLO-1234-",
                 "profile_ids": ["SG-1"],
                 "mac": "00:11:22:33:44:66",
                 "ipv6_gateway": "2001:db8:a41:2::1",
                 "ipv6_nets": ["2001:db8:a41:2::12/128"],
                 "state": "active",
                 "ipv4_nets": []},
            '/calico/v1/policy/profile/SG-1/rules':
                {"outbound_rules": [],
                 "inbound_rules": [{"dst_ports": ["5060:5061"],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4}]},
            '/calico/v1/policy/profile/SG-1/tags':
                ["SG-1"]
        }
        self.assertEtcdWrites(expected_writes)
        self.check_update_port_status_called(context)


        # Resync with all latest data - expect no etcd writes or deletes.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([]))

        # Change SG-1 to allow only port 5060.
        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5060,
            'port_range_max': 5060
        }
        self.notify_security_group_update(
            'SG-1',
            [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5060}
            ],
            None,
            'rule'
        )

        # Expect an etcd write
        expected_writes = {
            '/calico/v1/policy/profile/SG-1/rules':
                {"outbound_rules": [],
                 "inbound_rules": [{"dst_ports": [5060],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4}]},
            '/calico/v1/policy/profile/SG-1/tags':
                ["SG-1"]
        }
        self.assertEtcdWrites(expected_writes)

        # Resync with only the last port.  Expect the first two ports to be
        # cleaned up.
        self.osdb_ports = [context.original]
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([
            '/calico/v1/host/felix-host-1/workload/openstack/instance-1/endpoint/DEADBEEF-1234-5678',
            '/calico/v1/host/felix-host-1/workload/openstack/instance-2/endpoint/FACEBEEF-1234-5678'
        ]))

        # Change a small amount of information about the port and the security
        # group. Expect a resync to fix it up.
        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5070,
                 'port_range_max': 5071}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5070,
            'port_range_max': 5070
        }
        old_ips = self.osdb_ports[0]['fixed_ips']
        self.osdb_ports[0]['fixed_ips'] = [
            {'subnet_id': '10.65.0/24',
             'ip_address': '10.65.0.188'}
        ]
        print "\nResync with edited data\n"
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        expected_writes = {
            '/calico/v1/host/felix-host-2/workload/openstack/instance-3/endpoint/HELLO-1234-5678':
                {"name": "tapHELLO-1234-",
                 "profile_ids": ["SG-1"],
                 "mac": "00:11:22:33:44:66",
                 "ipv6_nets": [],
                 "state": "active",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.188/32"]},
            '/calico/v1/policy/profile/SG-1/rules':
                {"outbound_rules": [],
                 "inbound_rules": [{"dst_ports": [5070],
                                    "src_tag": "SGID-default",
                                    "ip_version": 4}]},
            '/calico/v1/policy/profile/SG-1/tags':
                ["SG-1"]
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Reset the state for safety.
        self.osdb_ports[0]['fixed_ips'] = old_ips

        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5060,
            'port_range_max': 5060
        }

    def test_noop_entry_points(self):
        """Call the mechanism driver entry points that are currently
        implemented as no-ops (because Calico function does not need
        them).
        """
        self.driver.update_subnet_postcommit(None)
        self.driver.update_network_postcommit(None)
        self.driver.delete_subnet_postcommit(None)
        self.driver.delete_network_postcommit(None)
        self.driver.create_network_postcommit(None)
        self.driver.create_subnet_postcommit(None)
        self.driver.update_network_postcommit(None)
        self.driver.update_subnet_postcommit(None)

    def test_check_segment_for_agent(self):
        """Test calls to the mechanism driver's check_segment_for_agent entry
        point.
        """
        # Simulate ML2 asking the driver if it can handle a port.
        self.assertTrue(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'flat',
             mech_calico.api.ID: 'shiny'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

        # Simulate ML2 asking the driver if it can handle a port that
        # it can't handle.
        self.assertFalse(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'vlan',
             mech_calico.api.ID: 'not-shiny'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

    def test_neutron_rule_to_etcd_rule_icmp(self):
        # No type/code specified
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
        }), {
            'ip_version': 4,
            'protocol': 'icmp',
            'src_net': '0.0.0.0/0',
        })
        # Type/code wildcarded, same as above.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
            "port_range_min": -1,
            "port_range_max": -1,
        }), {
            'ip_version': 4,
            'protocol': 'icmp',
            'src_net': '0.0.0.0/0',
        })
        # Type and code.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
            "port_range_min": 123,
            "port_range_max": 100,
        }), {
            'ip_version': 4,
            'protocol': 'icmp',
            'src_net': '0.0.0.0/0',
            'icmp_type': 123,
            'icmp_code': 100,
        })
        # Type and code, IPv6.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv6",
            "protocol": "icmp",
            "port_range_min": 123,
            "port_range_max": 100,
        }), {
            'ip_version': 6,
            'protocol': 'icmpv6',
            'src_net': '::/0',
            'icmp_type': 123,
            'icmp_code': 100,
        })

    def test_not_master_does_not_resync(self):
        """Test that a driver that is not master does not resync.
        """
        # Initialize the state early to put the elector in place, then override
        # it to claim that the driver is not master.
        self.driver._init_state()
        self.driver.transport.elector.master = lambda *args: False

        # Allow the etcd transport's resync thread to run. Nothing will happen.
        self.give_way()
        self.simulated_time_advance(31)
        self.assertEtcdWrites({})

    def test_not_master_does_not_poll(self):
        """
        Test that a driver that is not master does not poll.

        Master would read through etcd db and handle updates
        """
        # Initialize the state early to put the elector in place, then override
        # it to claim that the driver is not master.
        self.driver._init_state()
        self.driver.transport.elector.master = lambda *args: False

        self.driver._register_initial_felixes = mock.Mock()
        self.driver._handle_status_update = mock.Mock()

        # Allow the etcd transport's resync thread to run. Nothing will happen.
        self.give_way()
        self.simulated_time_advance(31)
        self.assertFalse(self.driver._register_initial_felixes.called)
        self.assertFalse(self.driver._handle_status_update.called)

    def test_status_subtree_read(self):
        """
        Test that initial read through etcd status subtree notices felixes.
        """
        # Add arbitrary status keys to accumulated etcd db
        self.etcd_data[FELIX_STATUS_DIR + "/vm_47/status"] = {"time": "2015-08-14T10:37:54"}
        self.etcd_data[FELIX_STATUS_DIR + "/vm_47/uptime"] = 12
        self.etcd_data[FELIX_STATUS_DIR + "/machine_123/uptime"] = 17
        self.etcd_data[FELIX_STATUS_DIR + "/VMachine/status"] = {"time": "1994-06-09T05:13:18"}

        expected_calls = [mock.call(None, TestIfAgentState(host="vm_47",
                                                           start_flag=True,
                                                           agent_type=mech_calico.AGENT_TYPE_FELIX,
                                                           binary='felix-calico-agent')),
                          mock.call(None, TestIfAgentState(host="machine_123",
                                                           start_flag=True,
                                                           agent_type=mech_calico.AGENT_TYPE_FELIX,
                                                           binary='felix-calico-agent'))]

        self.driver.db = mock.Mock()
        self.driver.transport = mock.Mock()
        self.driver.transport.status_client = self.client
        # Read through status subtree.
        self.driver._register_initial_felixes()
        self.driver.db.create_or_update_agent.assert_has_calls(expected_calls,
                                                               any_order=True)

        # Reset database
        self.etcd_data = []

    def test_status_response_handling(self):
        """
        Test that status update handling.
        """
        self.driver.db = mock.Mock()
        create_or_update_agent = self.driver.db.create_or_update_agent

        # Test status creation
        status_create = FakeResponse(key=FELIX_STATUS_DIR+"/VM_1/uptime",
                                     newKey=True)
        self.driver._handle_status_update(status_create)
        create_agent_state = TestIfAgentState(host="VM_1", start_flag=True)
        create_or_update_agent.assert_called_once(self.driver._db_context,
                                                  create_agent_state)
        create_or_update_agent.reset_mock()

        # Test status update
        status_update = FakeResponse(key=FELIX_STATUS_DIR+"/VM_2/uptime")
        self.driver._handle_status_update(status_update)
        update_agent_state = TestIfAgentState(host="VM_2", start_flag=False)
        create_or_update_agent.assert_called_once(self.driver._db_context,
                                                  update_agent_state)
        create_or_update_agent.reset_mock()

        # Test deleted status
        status_delete = FakeResponse(key=FELIX_STATUS_DIR+"/VM_3/uptime",
                                     action="delete")
        self.driver._handle_status_update(status_delete)
        self.assertFalse(create_or_update_agent.called)

        # Test expired status
        status_expire = FakeResponse(key=FELIX_STATUS_DIR+"/VM_4/uptime",
                                     action="expire")
        self.driver._handle_status_update(status_expire)
        self.assertFalse(create_or_update_agent.called)

        # Test not-uptime status
        status_not_uptime = FakeResponse(key=FELIX_STATUS_DIR+"/VM_5/not_uptime")
        self.driver._handle_status_update(status_not_uptime)
        self.assertFalse(create_or_update_agent.called)

    def test_etcd_index_increases_on_reads(self):
        """
        Test that index value is tracked when watching for status update.
        """
        self.driver.transport = mock.Mock()
        self.driver._handle_status_update = mock.Mock()

        lib.m_etcd.Client = lambda *args, **kwargs : self.client

        self.simulated_time_advance(31)

        old_etcd_index = self.driver.transport._next_etcd_index
        for new_update in xrange(15):
            self.give_way()
            self.simulated_time_advance(31)
            self.assertNotEqual(old_etcd_index,
                                self.driver.transport.next_etcd_index,
                                "etcd_index tracking error.")
            old_etcd_index = self.driver.transport.next_etcd_index

    def test_status_update_exceptions(self):
        """
        Test that exceptions causes reconnect/resync.
        """
        lib.m_etcd.Client = lambda *args, **kwargs : mock.Mock() #self.client
        self.driver.transport = t_etcd.CalicoTransportEtcd(self.driver)

        # Test ReadTimeoutError
        self.driver._handle_status_update = mock.Mock(side_effect=ReadTimeoutError('pool', 'url', 'Test ReadTimeoutError'))
        self.driver.transport.resync_status_tree = mock.Mock()
        # Poll - ReadTimeoutError is raised as side effect
        self.driver.transport._poll_and_handle_felix_updates(self.driver._epoch)
        self.assertFalse(self.driver.transport.resync_status_tree.called)

        # Test SocketTimeout
        self.driver._handle_status_update = mock.Mock(side_effect=SocketTimeout('Test SocketTimeout'))
        self.driver.transport.resync_status_tree = mock.Mock()
        # Poll - SocketTimeout is raised as as side effect
        self.driver.transport._poll_and_handle_felix_updates(self.driver._epoch)
        self.assertFalse(self.driver.transport.resync_status_tree.called)

        # Test EtcdClusterIdChanged
        self.driver._handle_status_update = mock.Mock(side_effect=EtcdClusterIdChanged("Test EtcdClusterIdChanged"))
        self.driver.transport.resync_status_tree = mock.Mock()
        # Poll - EtcdClusterIdChanged is raised as side effect
        self.driver.transport._poll_and_handle_felix_updates(self.driver._epoch)
        self.assertTrue(self.driver.transport.resync_status_tree.called)

        # Test EtcdEventIndexCleared
        self.driver._handle_status_update = mock.Mock(side_effect=EtcdEventIndexCleared("Test EtcdEventIndexCleared"))
        self.driver.transport.resync_status_tree = mock.Mock()
        # Poll - EtcdEventIndexCleared is raised as side effect
        self.driver.transport._poll_and_handle_felix_updates(self.driver._epoch)
        self.assertTrue(self.driver.transport.resync_status_tree.called)

        # Test general exception
        self.driver._handle_status_update = mock.Mock(side_effect=[Exception("Test general exception")])
        self.driver.transport.resync_status_tree = mock.Mock()
        # Poll - ReadTimeoutError is raised as side effect
        self.driver.transport._poll_and_handle_felix_updates(self.driver._epoch)
        self.assertFalse(self.driver.transport.resync_status_tree.called)

    def assertNeutronToEtcd(self, neutron_rule, exp_etcd_rule):
        etcd_rule = t_etcd._neutron_rule_to_etcd_rule(neutron_rule)
        self.assertEqual(etcd_rule, exp_etcd_rule)

        # Check felix is happy with generated rule.
        if neutron_rule["direction"] == "ingress":
            rules = {"inbound_rules": [etcd_rule],
                     "outbound_rules": []}
        else:
            rules = {"outbound_rules": [etcd_rule],
                     "inbound_rules": []}
        common.validate_rules("profile_id", rules)


def _neutron_rule_from_dict(overrides):
    rule = {
        "ethertype": "IPv4",
        "protocol": None,
        "remote_ip_prefix": None,
        "remote_group_id": None,
        "direction": "ingress",
        "port_range_min": None,
        "port_range_max": None,
    }
    rule.update(overrides)
    return rule

class TestIfAgentState(object):
    """
    Class to help decide if object is agent_state

    :param: kwargs for agent attributes.
    """
    def __init__(self, agent_type=None, binary=None, host=None, topic=None, start_flag=None):
        self.agent_type = agent_type
        self.binary = binary
        self.host = host
        self.topic = topic
        self.start_flag = start_flag
    def __eq__(self, other):
        if type(other) != dict:
            return False
        if self.agent_type != None and other["agent_type"] != self.agent_type:
            return False
        if self.binary != None and other["binary"] != self.binary:
            return False
        if self.host != None and other["host"] != self.host:
            return False
        if self.topic != None and other["topic"] != self.topic:
            return False
        if self.start_flag and not other.get("start_flag"):
            return False
        if self.start_flag == False and other.get("start_flag"):
            return False
        return  True

class FakeResponse(object):
    """
    Class to simulate an etcd response.

    :param: kwargs for response attributes
    """
    def __init__(self, action=None, key="/", newKey=False, **kwargs):
        self.action = action
        self.key = key
        self.newKey = newKey
        for key, value in kwargs.iteritems():
            self.key = value
