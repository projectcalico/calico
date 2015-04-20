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
from calico.felix import fetcd

import calico.openstack.test.lib as lib
import calico.openstack.mech_calico as mech_calico
import calico.openstack.t_etcd as t_etcd


class EtcdKeyNotFound(BaseException):
    pass

lib.m_etcd.EtcdKeyNotFound = EtcdKeyNotFound


class TestPluginEtcd(lib.Lib, unittest.TestCase):

    def maybe_reset_etcd(self):
        if self.reset_etcd_after is not None:
            self.reset_etcd_after -= 1
            if self.reset_etcd_after == 0:
                self.etcd_data = {}
                self.reset_etcd_after = None
                print "etcd reset"
                self.assert_etcd_writes_deletes = False

    def check_etcd_write(self, key, value):
        """Print each etcd write as it occurs, and save into the accumulated etcd
        database.
        """
        self.maybe_reset_etcd()
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
            del self.etcd_data[key]
            self.recent_deletes.add(key)

    def assertEtcdWrites(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(self.recent_writes, expected)
        self.recent_writes = {}

    def assertEtcdDeletes(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(self.recent_deletes, expected)
        self.recent_deletes = set()

    def etcd_read(self, key, recursive=False):
        """Read from the accumulated etcd database.
        """
        self.maybe_reset_etcd()

        # Prepare a read result object.
        read_result = mock.Mock()
        read_result.key = key

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
            print "children: %s" % [child.key
                                    for child in read_result.children]
            if read_result.value is None and read_result.children == []:
                raise lib.m_etcd.EtcdKeyNotFound()
        else:
            read_result.children = None

        return read_result

    def setUp(self):
        """Setup before each test case.
        """
        # Do common plugin test setup.
        super(TestPluginEtcd, self).setUp()

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

        # Reset the counter for when we'll reset the etcd database.
        self.reset_etcd_after = None
        self.assert_etcd_writes_deletes = True

    def test_start_no_ports(self):
        """Startup with no ports or existing etcd data.
        """
        # Tell the driver to initialize.
        self.driver.initialize()

        # Allow the etcd transport's resync thread to run.
        self.give_way()
        self.simulated_time_advance(1)
        self.assertEtcdWrites({'/calico/v1/config/InterfacePrefix': 'tap',
                               '/calico/v1/Ready': True})

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

        # Tell the driver to initialize.
        self.driver.initialize()

        # Allow the etcd transport's resync thread to run.
        self.give_way()
        self.simulated_time_advance(1)
        expected_writes = {
            '/calico/v1/config/InterfacePrefix': 'tap',
            '/calico/v1/Ready': True,
            '/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []},
            '/calico/v1/host/felix-host-1/workload/openstack/FACEBEEF-1234-5678/endpoint/FACEBEEF-1234-5678':
                {"name": "tapFACEBEEF-12",
                 "profile_id": "SGID-default",
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
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Delete lib.port1
        context = mock.Mock()
        context._port = lib.port1
        self.driver.delete_port_postcommit(context)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set(['/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678']))
        self.osdb_ports = [lib.port2]

        # Do another resync - expect no changes to the etcd data.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Add lib.port1 back again.
        self.driver.create_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
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
        self.osdb_ports = [lib.port1, lib.port2]

        # Migrate port1 to a different host.
        context._port = lib.port1.copy()
        context._port['binding:host_id'] = 'new-host'
        context.original = lib.port1
        self.driver.update_port_postcommit(context)
        del expected_writes['/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678']
        expected_writes['/calico/v1/host/new-host/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678'] = {
            "name": "tapDEADBEEF-12",
            "profile_id": "SGID-default",
            "mac": "00:11:22:33:44:55",
            "ipv4_gateway": "10.65.0.1",
            "ipv4_nets": ["10.65.0.2/32"],
            "state": "active",
            "ipv6_nets": []
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678']))

        # Now resync again without updating self.osdb_ports to reflect that
        # port1 has moved to new-host.  The effect will be as though we've
        # missed a further update that moved port1 back to felix-host-1; this
        # resync will now discover that.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        expected_writes = {
            '/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678':
                {"name": "tapDEADBEEF-12",
                 "profile_id": "SGID-default",
                 "mac": "00:11:22:33:44:55",
                 "ipv4_gateway": "10.65.0.1",
                 "ipv4_nets": ["10.65.0.2/32"],
                 "state": "active",
                 "ipv6_nets": []}
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set(['/calico/v1/host/new-host/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678']))

        # Add another port with an IPv6 address.
        context._port = lib.port3.copy()
        self.driver.create_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-2/workload/openstack/HELLO-1234-5678/endpoint/HELLO-1234-5678':
                {"name": "tapHELLO-1234-",
                 "profile_id": "SGID-default",
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
        self.assertEtcdWrites({})

        # Now change the security group for that port.
        context.original = context._port.copy()
        context._port['security_groups'] = ['SG-1']
        self.driver.update_port_postcommit(context)
        expected_writes = {
            '/calico/v1/host/felix-host-2/workload/openstack/HELLO-1234-5678/endpoint/HELLO-1234-5678':
                {"name": "tapHELLO-1234-",
                 "profile_id": "SG-1",
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

        # Update what the DB's get_security_groups query should now return.
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

        # Resync with all latest data - expect no etcd writes or deletes.
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([]))

        # Change SG-1 to allow only port 5060.
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

        # Expect an etcd write because SG-1 is now in use.
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
        # cleaned up, and also SGID-default, because now only SG-1 is needed.
        self.osdb_ports = [context._port]
        self.db.get_security_groups.return_value[1]['security_group_rules'][0]['port_range_max'] = 5060
        print "\nResync with existing etcd data\n"
        self.simulated_time_advance(t_etcd.PERIODIC_RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([
            '/calico/v1/host/felix-host-1/workload/openstack/DEADBEEF-1234-5678/endpoint/DEADBEEF-1234-5678',
            '/calico/v1/host/felix-host-1/workload/openstack/FACEBEEF-1234-5678/endpoint/FACEBEEF-1234-5678',
            '/calico/v1/policy/profile/SGID-default(recursive)']))

    def test_noop_entry_points(self):
        """Call the mechanism driver entry points that are currently
        implemented as no-ops (because Calico function does not need
        them).
        """
        self.driver.initialize()
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
        self.driver.initialize()

        # Simulate ML2 asking the driver if it can handle a port.
        self.assertTrue(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'flat'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

        # Simulate ML2 asking the driver if it can handle a port that
        # it can't handle.
        self.assertFalse(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'vlan'},
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

    def assertNeutronToEtcd(self, neutron_rule, exp_etcd_rule):
        etcd_rule = t_etcd._neutron_rule_to_etcd_rule(neutron_rule)
        self.assertEqual(etcd_rule, exp_etcd_rule)

        # Check felix is happy with generated rule.
        if neutron_rule["direction"] == "ingress":
            rules = {"inbound_rules": [neutron_rule],
                     "outbound_rules": []}
        else:
            rules = {"outbound_rules": [neutron_rule],
                     "inbound_rules": []}
        fetcd.validate_rules(rules)


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
