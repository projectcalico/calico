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
import unittest
import uuid
from contextlib import nested

import calico.felix.devices as devices
import calico.felix.endpoint as endpoint
import calico.felix.frules as frules
import calico.felix.futils as futils

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
