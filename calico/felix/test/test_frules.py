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
felix.test.test_frules
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables rules generation function.
"""
import logging
from mock import Mock, patch, call
from calico.felix import frules
from calico.felix.fiptables import IptablesUpdater
from calico.felix.futils import FailedSystemCall
from calico.felix.test.base import BaseTestCase, load_config

_log = logging.getLogger(__name__)


class TestRules(BaseTestCase):

    @patch("calico.felix.futils.check_call", autospec=True)
    @patch("calico.felix.frules.devices", autospec=True)
    @patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    def test_install_global_rules(self, m_ipset, m_devices, m_check_call):
        m_devices.interface_exists.return_value = False
        m_devices.interface_up.return_value = False

        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_HOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAADDR": "123.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "True",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTENDPOINTTOHOSTACTION": "RETURN"
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)

        m_v4_upd = Mock(spec=IptablesUpdater)
        m_v6_upd = Mock(spec=IptablesUpdater)
        m_v6_raw_upd = Mock(spec=IptablesUpdater)
        m_v4_nat_upd = Mock(spec=IptablesUpdater)

        frules.install_global_rules(config, m_v4_upd, m_v6_upd, m_v4_nat_upd,
                                    m_v6_raw_upd)

        m_v6_raw_upd.ensure_rule_inserted.assert_called_once_with(
            'PREROUTING --in-interface tap+ --match rpfilter --invert --jump '
            'felix-PREROUTING',
            async=False,
        )
        m_v6_raw_upd.rewrite_chains.assert_called_once_with(
            {'felix-PREROUTING': [
                '--append felix-PREROUTING --jump DROP -m comment '
                '--comment "IPv6 rpfilter failed"'
            ]},
            {
                'felix-PREROUTING': {}
            },
            async=False
        )

        m_ipset.ensure_exists.assert_called_once_with()
        self.assertEqual(
            m_check_call.mock_calls,
            [
                call(["ip", "tunnel", "add", "tunl0", "mode", "ipip"]),
                call(["ip", "link", "set", "tunl0", "mtu", "1480"]),
                call(["ip", "link", "set", "tunl0", "up"]),
            ]
        )

        expected_chains = {
            'felix-INPUT': [
                '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
                '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
                '--append felix-INPUT --jump felix-FROM-ENDPOINT'
            ],
            'felix-FORWARD': [
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump RETURN',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump RETURN',
                '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
                '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --out-interface tap+'
            ]
        }
        m_v4_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            {
                'felix-INPUT': set(['felix-FROM-ENDPOINT']),
                'felix-FORWARD': set([
                    'felix-FROM-ENDPOINT',
                    'felix-TO-ENDPOINT'
                ])
            },
            async=False
        )

        self.assertEqual(
            m_v4_upd.ensure_rule_inserted.mock_calls,
            [
                call("INPUT --jump felix-INPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False),
            ]
        )

    def test_install_global_rules_retries_ipip(self):
        m_config = Mock()
        m_config.IFACE_PREFIX = "tap"
        m_config.IP_IN_IP_ENABLED = True
        with patch("calico.felix.frules._configure_ipip_device") as m_ipip:
            m_ipip.side_effect = FailedSystemCall("", [], 1, "", "")
            self.assertRaises(FailedSystemCall,
                              frules.install_global_rules,
                              m_config, None, None, None, None)
            self.assertEqual(m_ipip.mock_calls,
                             [
                                 call(m_config),
                                 call(m_config)
                             ])