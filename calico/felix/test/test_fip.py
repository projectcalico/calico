# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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

import collections
import mock

from calico.felix.test.base import BaseTestCase
from calico.felix.fipmanager import FloatingIPManager
from calico.felix.frules import CHAIN_FIP_DNAT, CHAIN_FIP_SNAT

Config = collections.namedtuple('Config', ['IFACE_PREFIX', 'METADATA_IP',
                                           'METADATA_PORT'])


class TestFloatingIPs(BaseTestCase):
    def setUp(self):
        super(TestFloatingIPs, self).setUp()
        self.iptables_updater = mock.MagicMock()
        self.config = Config('tap', None, 8775)

    def get_floating_ip_manager(self, ip_version):
        return FloatingIPManager(
            config=self.config,
            ip_version=ip_version,
            iptables_updater=self.iptables_updater
        )

    def _run_fip_manager_loop(self, ip_version, runs):
        self.config = Config('tap', '127.0.0.1', 8775)
        f = self.get_floating_ip_manager(ip_version)

        for maps, expected_dnat, expected_snat in runs:
            f.update_endpoint('endpoint_id', maps, async=True)
            self.step_actor(f)

            actual_calls = self.iptables_updater.rewrite_chains.mock_calls
            expected_calls = [
                mock.call({CHAIN_FIP_DNAT: expected_dnat,
                           CHAIN_FIP_SNAT: expected_snat}, {}, async=True)
            ]

            self.assertEqual(actual_calls, expected_calls)
            self.iptables_updater.rewrite_chains.reset_mock()


    def test_fip_manager_ipv4(self):
        maps = [{'int_ip': '10.0.0.1', 'ext_ip': '192.168.0.1'}]
        expected_dnat = [
            '--append %s -d 192.168.0.1 -j DNAT --to-destination 10.0.0.1' % CHAIN_FIP_DNAT,
        ]
        expected_snat = [
            '--append %s -s 10.0.0.1 -d 10.0.0.1 -j SNAT --to-source 192.168.0.1' % CHAIN_FIP_SNAT,
        ]

        self._run_fip_manager_loop(4, [
            # Test add.
            (maps, expected_dnat, expected_snat),
            # Test delete.
            ([], [], [])
        ])

    def test_fip_manager_ipv6(self):
        maps = [{'int_ip': '1000:0000:0000:0000:0000:0001', 'ext_ip': 'ffff:0000:0000:0000:0000:0001'}]
        expected_dnat = [
            '--append %s -d ffff:0000:0000:0000:0000:0001 -j DNAT --to-destination '
                '1000:0000:0000:0000:0000:0001' % CHAIN_FIP_DNAT,
        ]
        expected_snat = [
            '--append %s -s 1000:0000:0000:0000:0000:0001 -d '
            '1000:0000:0000:0000:0000:0001 -j SNAT --to-source ffff:0000:0000:0000:0000:0001' %
            CHAIN_FIP_SNAT
        ]

        self._run_fip_manager_loop(6, [
            # Test add.
            (maps, expected_dnat, expected_snat),
            # Test delete.
            ([], [], [])
        ])
