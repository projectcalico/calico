# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
felix.test.test_endpoint
~~~~~~~~~~~~~~~~~~~~~~~~

Test the endpoint handling code.
"""
import mock
import sys
import uuid
from contextlib import nested
from netaddr import IPAddress

import calico.felix.devices as devices
import calico.felix.endpoint as endpoint
import calico.felix.frules as frules
import calico.felix.futils as futils
from calico.felix.exceptions import InvalidRequest

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from collections import namedtuple
Config = namedtuple('Config', ['IFACE_PREFIX', 'SUFFIX_LEN'])

# Supplied, but never accessed thanks to mocks.
iptables_state = None

config = Config("tap", 11)

class TestEndpoint(unittest.TestCase):
    def test_program_bails_early(self):
        """
        Test that programming an endpoint fails early if the endpoint is down.
        """
        devices.interface_up = mock.MagicMock()
        devices.interface_up.return_value = False

        # iptables_state is never accessed (as the code returns too early).
        iptables_state = None

        ep_id = str(uuid.uuid4())
        prefix = "tap"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        retval = ep.program_endpoint(iptables_state)

        self.assertFalse(retval)

    def test_remove_deleted(self):
        """
        Removal of an endpoint where tap interface deleted under our feet.
        """
        ep_id = str(uuid.uuid4())
        prefix = "tap"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)

        p_exists = mock.patch('calico.felix.devices.interface_exists',
                              side_effect=[True, False])
        p_list = mock.patch('calico.felix.devices.list_interface_ips',
                            return_value = set(["1.2.3.4", "1.2.3.5"]))
        p_del_route = mock.patch('calico.felix.devices.del_route',
            side_effect=futils.FailedSystemCall("blah",
                                                ["dummy", "args"],
                                                1,
                                                "",
                                                ""))
        p_del_rules = mock.patch('calico.felix.frules.del_rules')

        with nested(p_exists, p_list, p_del_route, p_del_rules) as (
            mock_exists, mock_list, mock_del_route, mock_del_rules):
            ep.remove(iptables_state)
        self.assertEqual(mock_exists.call_count, 2)
        self.assertEqual(mock_list.call_count, 1)
        self.assertEqual(mock_del_route.call_count, 1)
        self.assertEqual(mock_del_rules.call_count, 2)

    def test_remove_sys_error(self):
        """
        Removal of an endpoint where other system error happens.
        """
        ep_id = str(uuid.uuid4())
        prefix = "tap"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)

        with self.assertRaisesRegexp(futils.FailedSystemCall, "blah"):
            p_exists = mock.patch('calico.felix.devices.interface_exists',
                                  side_effect=[True, True])
            p_list = mock.patch('calico.felix.devices.list_interface_ips',
                                return_value = set(["1.2.3.4", "1.2.3.5"]))
            p_del_route = mock.patch('calico.felix.devices.del_route',
                side_effect=futils.FailedSystemCall("blah",
                                                    ["dummy", "args"],
                                                    1,
                                                    "",
                                                    ""))
            p_del_rules = mock.patch('calico.felix.frules.del_rules')
            with nested(p_exists, p_list, p_del_route, p_del_rules) as (
                mock_exists, mock_list, mock_del_route, mock_del_rules):
                ep.remove(iptables_state)

        self.assertEqual(mock_exists.call_count, 2)
        self.assertEqual(mock_list.call_count, 1)
        self.assertEqual(mock_del_route.call_count, 1)
        self.assertEqual(mock_del_rules.call_count, 0)

    def test_remove_other_error(self):
        """
        Removal of an endpoint where some random exception appears.
        """
        ep_id = str(uuid.uuid4())
        prefix = "tap"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)

        with self.assertRaisesRegexp(Exception, "blah"):
            p_exists = mock.patch('calico.felix.devices.interface_exists',
                                  side_effect=[True, True])
            p_list = mock.patch('calico.felix.devices.list_interface_ips',
                                return_value = set(["1.2.3.4", "1.2.3.5"]))
            p_del_route = mock.patch('calico.felix.devices.del_route',
                                     side_effect=Exception("blah"))
            p_del_rules = mock.patch('calico.felix.frules.del_rules')
            with nested(p_exists, p_list, p_del_route, p_del_rules) as (
                mock_exists, mock_list, mock_del_route, mock_del_rules):
                ep.remove(iptables_state)

        self.assertEqual(mock_exists.call_count, 1)
        self.assertEqual(mock_list.call_count, 1)
        self.assertEqual(mock_del_route.call_count, 1)
        self.assertEqual(mock_del_rules.call_count, 0)

    def test_store_update_valid(self):
        """
        Test that store update works for valid data.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        fields = {u'mac': u'11:22:33:44:55:66',
                  u'state': u'enabled',
                  u'addrs': [{u"addr": u"10.0.65.2",
                              u"gateway": u"10.0.65.1",
                              u"properties": {u"gr": False}
                             }]
                  }
        ep.store_update(fields)
        self.assertEqual(ep.state, "enabled")
        self.assertEqual(ep.mac, "11:22:33:44:55:66")
        self.assertEqual(len(ep.addresses), 1)
        (ip, addr) = ep.addresses.popitem()
        self.assertEqual(ip, addr.ip)
        self.assertEqual(addr.ip, IPAddress("10.0.65.2"))
        self.assertEqual(addr.gateway, IPAddress("10.0.65.1"))

        # Now, modify one of the addresses and update again.
        fields[u'addrs'][0][u'addr'] = u'10.34.66.1'
        ep.store_update(fields)
        self.assertEqual(ep.state, "enabled")
        self.assertEqual(ep.mac, "11:22:33:44:55:66")
        self.assertEqual(len(ep.addresses), 1)
        (ip, addr) = ep.addresses.popitem()
        self.assertEqual(ip, addr.ip)
        self.assertEqual(addr.ip, IPAddress("10.34.66.1"))
        self.assertEqual(addr.gateway, IPAddress("10.0.65.1"))

    def test_store_update_no_addrs(self):
        """
        Test that store update works even if there are no addresses.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        fields = {u'mac': u'11:22:33:44:55:66',
                  u'state': u'enabled',
                  u'addrs': []
                  }
        ep.store_update(fields)
        self.assertEqual(ep.state, "enabled")
        self.assertEqual(ep.mac, "11:22:33:44:55:66")
        self.assertEqual(len(ep.addresses), 0)

    def test_store_update_2_addrs(self):
        """
        Test that store update works for multiple IP addresses.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        # Mix ascii and unicode to make sure we cope.
        fields = {u'mac': '11:22:33:44:55:66',
                  'state': u'enabled',
                  u'addrs': [{u'addr': '10.0.65.2',
                              "gateway": u"10.0.65.1",
                              u"properties": {u"gr": False}
                             },
                             {"addr": u"2001::3:4",
                              u"gateway": "2001::1",
                              "properties": {"gr": False}
                             },]
                  }
        ep.store_update(fields)
        self.assertEqual(ep.state, "enabled")
        self.assertEqual(ep.mac, "11:22:33:44:55:66")
        self.assertEqual(len(ep.addresses), 2)

        # Set comprehension to get the 2 IP addresses
        ips = set(address.ip for address in ep.addresses.values())
        self.assertSetEqual(ips, set([IPAddress("10.0.65.2"),
                                      IPAddress("2001::3:4")]))

        # Set comprehension to get the gateways
        gws = set(address.gateway for address in ep.addresses.values())
        self.assertSetEqual(gws, set([IPAddress("10.0.65.1"),
                                      IPAddress("2001::1")]))

    def test_store_update_2_addrs_repeated(self):
        """
        Test that store update throws an exception if an address is repeated.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        # Mix ascii and unicode to make sure we cope.
        fields = {u'mac': '11:22:33:44:55:66',
                  'state': u'enabled',
                  u'addrs': [{u'addr': '10.0.65.2',
                              "gateway": u"10.0.65.1",
                              u"properties": {u"gr": False}
                             },
                             {u'addr': '10.0.65.2',
                              "gateway": u"10.0.65.10",
                              u"properties": {u"gr": True}
                             },]
                  }
        self.assertRaises(InvalidRequest, ep.store_update, fields)

    def test_store_update_ip_gw_mismatch(self):
        """
        Test that store update throws an exception if a IP and gateway are
        different versions.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        # Mix ascii and unicode to make sure we cope.
        fields = {u'mac': '11:22:33:44:55:66',
                  'state': u'enabled',
                  u'addrs': [{u'addr': '10.0.65.2',
                              "gateway": u"2001::10:0:65:4",
                              u"properties": {u"gr": False}
                             },]
                  }
        self.assertRaises(InvalidRequest, ep.store_update, fields)

    def test_store_update_no_ip(self):
        """
        Test that store update throws an exception if a IP and gateway are
        different versions.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        # Mix ascii and unicode to make sure we cope.
        fields = {u'mac': '11:22:33:44:55:66',
                  'state': u'enabled',
                  u'addrs': [{"gateway": u"2001::10:0:65:4",
                              u"properties": {u"gr": False}
                             },]
                  }
        self.assertRaises(InvalidRequest, ep.store_update, fields)

    def test_store_update_no_gw(self):
        """
        Test that store update works for valid data.
        """
        ep_id = str(uuid.uuid4())
        prefix = "vth"
        interface = prefix + ep_id[:11]
        ep = endpoint.Endpoint(ep_id,
                               'aa:bb:cc:dd:ee:ff',
                               interface,
                               prefix)
        fields = {u'mac': u'11:22:33:44:55:66',
                  u'state': u'enabled',
                  u'addrs': [{u"addr": u"10.0.65.2",
                              u"properties": {u"gr": False}
                             }]
                  }
        ep.store_update(fields)
        self.assertEqual(ep.state, "enabled")
        self.assertEqual(ep.mac, "11:22:33:44:55:66")
        self.assertEqual(len(ep.addresses), 1)
        (ip, addr) = ep.addresses.popitem()
        self.assertEqual(ip, addr.ip)
        self.assertEqual(addr.ip, IPAddress("10.0.65.2"))
        self.assertEqual(addr.gateway, None)
