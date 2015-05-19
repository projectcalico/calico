# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
test.test_common
~~~~~~~~~~~

Test common utility code.
"""
import copy
import logging
import mock
import os
import unittest

import calico.common as common


# Logger
_log = logging.getLogger(__name__)


MISSING = object()


class TestCommon(unittest.TestCase):
    def setUp(self):
        self.m_config = mock.Mock()
        self.m_config.IFACE_PREFIX = "tap"

    def tearDown(self):
        pass

    def test_validate_port(self):
        self.assertFalse(common.validate_port(-1))
        self.assertFalse(common.validate_port(0))
        self.assertTrue(common.validate_port(3))
        self.assertTrue(common.validate_port(3))
        self.assertTrue(common.validate_port(65535))
        self.assertFalse(common.validate_port(65536))
        self.assertFalse(common.validate_port("-1"))
        self.assertFalse(common.validate_port("0"))
        self.assertTrue(common.validate_port("3"))
        self.assertTrue(common.validate_port("3"))
        self.assertTrue(common.validate_port("65535"))
        self.assertFalse(common.validate_port("65536"))
        self.assertFalse(common.validate_port("1-10"))
        self.assertFalse(common.validate_port("blah"))

    def test_validate_endpoint_mainline(self):
        endpoint = {
            "state": "active",
            "name": "tap1234",
            "mac": "AA:bb:cc:dd:ee:ff",
            "ipv4_nets": ["10.0.1/32"],
            "ipv4_gateway": "11.0.0.1",
            "ipv6_nets": ["2001:0::1/64"],
            "ipv6_gateway": "fe80:0::1",
            "profile_id": "prof1",
        }
        common.validate_endpoint(self.m_config, endpoint)
        self.assertEqual(endpoint, {
            'state': 'active',
            'name': 'tap1234',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ipv4_nets': ['10.0.1.0/32'],
            'ipv4_gateway': '11.0.0.1',
            'ipv6_nets': ['2001::1/64'],
            'ipv6_gateway': 'fe80::1',
            'profile_ids':['prof1'],
        })

    def test_validate_endpoint_mainline_profile_ids(self):
        endpoint = {
            "state": "active",
            "name": "tap1234",
            "mac": "AA-bb-cc-dd-ee-ff",
            "ipv4_nets": ["10.0.1/32"],
            "profile_ids": ["prof1", "prof2"],
        }
        common.validate_endpoint(self.m_config, endpoint)
        self.assertEqual(endpoint, {
            'state': 'active',
            'name': 'tap1234',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ipv4_nets': ['10.0.1.0/32'],
            "ipv6_nets": [],
            "profile_ids": ["prof1", "prof2"],
        })

    def test_validate_endpoint_failures(self):
        self.assert_invalid_endpoint([])
        self.assert_invalid_endpoint("foo")
        self.assert_invalid_endpoint("foo")

        self.assert_tweak_invalidates_endpoint(state=MISSING)
        self.assert_tweak_invalidates_endpoint(state=None)
        self.assert_tweak_invalidates_endpoint(state="foo")

        self.assert_tweak_invalidates_endpoint(name=MISSING)
        self.assert_tweak_invalidates_endpoint(name=None)
        self.assert_tweak_invalidates_endpoint(name=object())
        self.assert_tweak_invalidates_endpoint(name=[])
        self.assert_tweak_invalidates_endpoint(name="incorrect_prefix")

        self.assert_tweak_invalidates_endpoint(mac=MISSING)
        self.assert_tweak_invalidates_endpoint(mac=None)
        self.assert_tweak_invalidates_endpoint(mac=object())
        self.assert_tweak_invalidates_endpoint(mac="bad MAC")

        self.assert_tweak_invalidates_endpoint(profile_id=MISSING)
        self.assert_tweak_invalidates_endpoint(profile_id=None)
        self.assert_tweak_invalidates_endpoint(profile_id=[])

        self.assert_tweak_invalidates_endpoint(ipv4_gateway="not an IP")
        self.assert_tweak_invalidates_endpoint(ipv4_gateway=[])

        self.assert_tweak_invalidates_endpoint(ipv6_gateway="not an IP")
        self.assert_tweak_invalidates_endpoint(ipv6_gateway=[])

        self.assert_tweak_invalidates_endpoint(ipv4_nets="not a list")
        self.assert_tweak_invalidates_endpoint(ipv4_nets={})
        self.assert_tweak_invalidates_endpoint(ipv4_nets=["not an IP"])
        self.assert_tweak_invalidates_endpoint(ipv4_nets=["12345"])
        self.assert_tweak_invalidates_endpoint(ipv4_nets=["1234::1/64"])

        self.assert_tweak_invalidates_endpoint(ipv6_nets="not a list")
        self.assert_tweak_invalidates_endpoint(ipv6_nets={})
        self.assert_tweak_invalidates_endpoint(ipv6_nets=["not an IP"])
        self.assert_tweak_invalidates_endpoint(ipv6_nets=["12345"])
        self.assert_tweak_invalidates_endpoint(ipv6_nets=["10.0.0.0/8"])

    def assert_invalid_endpoint(self, bad_value):
        self.assertRaises(common.ValidationFailed, common.validate_endpoint,
                          self.m_config, bad_value)

    def assert_endpoint_valid(self, original_endpoint):
        endpoint = copy.deepcopy(original_endpoint)
        try:
            # First pass at validation, may canonicalise the data.
            common.validate_endpoint(self.m_config, endpoint)
            canonical_endpoint = copy.deepcopy(endpoint)
            # Second pass, should make no changes.
            common.validate_endpoint(self.m_config, canonical_endpoint)
            self.assertEqual(endpoint, canonical_endpoint)
        except common.ValidationFailed as e:
            _log.exception("Validation unexpectedly failed for %s",
                           original_endpoint)
            self.fail("Validation unexpectedly failed for %s: %r" %
                      original_endpoint, e)

    def assert_tweak_invalidates_endpoint(self, **tweak):
        valid_endpoint = {
            "state": "active",
            "name": "tap1234",
            "mac": "AA:bb:cc:dd:ee:ff",
            "ipv4_nets": ["10.0.1/32"],
            "ipv4_gateway": "11.0.0.1",
            "ipv6_nets": ["2001:0::1/64"],
            "ipv6_gateway": "fe80:0::1",
            "profile_id": "prof1",
        }
        self.assert_endpoint_valid(valid_endpoint)
        invalid_endpoint = valid_endpoint.copy()
        for key, value in tweak.iteritems():
            if value is MISSING:
                invalid_endpoint.pop(key)
            else:
                invalid_endpoint[key] = value
        self.assert_invalid_endpoint(invalid_endpoint)

    def test_validate_rules(self):
        rules = {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10/8",
                 "dst_net": "11.0/16", "src_ports": [10, "11:12"],
                 "action": "allow"},
                {"protocol": "tcp", "src_net": None},
            ],
            "outbound_rules": [
                {"protocol": "tcp", "ip_version": 6,
                 "src_net": "2001:0::1/128", "dst_net": "2001:0::/64",
                 "icmp_type": 7, "icmp_code": 10,
                 "action": "deny"}
            ],
        }
        common.validate_rules(rules)
        # Check IPs get made canonical.
        self.assertEqual(rules, {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10.0.0.0/8",
                 "dst_net": "11.0.0.0/16", "src_ports": [10, "11:12"],
                 "action": "allow"},
                {"protocol": "tcp"},
            ],
            "outbound_rules": [
                {"protocol": "tcp", "ip_version": 6,
                 "src_net": "2001::1/128", "dst_net": "2001::/64",
                 "icmp_type": 7, "icmp_code": 10,
                 "action": "deny"}
            ],
        })

    def test_validate_ip_addr(self):
        self.assertTrue(common.validate_ip_addr("1.2.3.4", 4))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", 4))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", 4))
        self.assertTrue(common.validate_ip_addr("1.2.3", 4))
        self.assertFalse(common.validate_ip_addr("bloop", 4))
        self.assertFalse(common.validate_ip_addr("::", 4))
        self.assertFalse(common.validate_ip_addr("2001::abc", 4))
        self.assertFalse(common.validate_ip_addr("2001::a/64", 4))

        self.assertFalse(common.validate_ip_addr("1.2.3.4", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3", 6))
        self.assertFalse(common.validate_ip_addr("bloop", 6))
        self.assertTrue(common.validate_ip_addr("::", 6))
        self.assertTrue(common.validate_ip_addr("2001::abc", 6))
        self.assertFalse(common.validate_ip_addr("2001::a/64", 6))

        self.assertTrue(common.validate_ip_addr("1.2.3.4", None))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", None))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", None))
        self.assertTrue(common.validate_ip_addr("1.2.3", None))
        self.assertFalse(common.validate_ip_addr("bloop", None))
        self.assertTrue(common.validate_ip_addr("::", None))
        self.assertTrue(common.validate_ip_addr("2001::abc", None))
        self.assertFalse(common.validate_ip_addr("2001::a/64", None))

        self.assertFalse(common.validate_ip_addr(None, None))

    def test_validate_cidr(self):
        self.assertTrue(common.validate_cidr("1.2.3.4", 4))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 4))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", 4))
        self.assertTrue(common.validate_cidr("1.2.3", 4))
        self.assertFalse(common.validate_cidr("bloop", 4))
        self.assertFalse(common.validate_cidr("::", 4))
        self.assertFalse(common.validate_cidr("2001::abc", 4))
        self.assertFalse(common.validate_cidr("2001::a/64", 4))

        self.assertFalse(common.validate_cidr("1.2.3.4", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4/32", 6))
        self.assertFalse(common.validate_cidr("1.2.3", 6))
        self.assertFalse(common.validate_cidr("bloop", 6))
        self.assertTrue(common.validate_cidr("::", 6))
        self.assertTrue(common.validate_cidr("2001::abc", 6))
        self.assertTrue(common.validate_cidr("2001::a/64", 6))

        self.assertTrue(common.validate_cidr("1.2.3.4", None))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", None))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", None))
        self.assertTrue(common.validate_cidr("1.2.3", None))
        self.assertFalse(common.validate_cidr("bloop", None))
        self.assertTrue(common.validate_cidr("::", None))
        self.assertTrue(common.validate_cidr("2001::abc", None))
        self.assertTrue(common.validate_cidr("2001::a/64", None))

        self.assertFalse(common.validate_cidr(None, None))

    def test_canonicalise_ip(self):
        self.assertTrue(common.canonicalise_ip("1.2.3.4", 4), "1.2.3.4")
        self.assertTrue(common.canonicalise_ip("1.2.3", 4), "1.2.3.0")

        self.assertTrue(common.canonicalise_ip("2001::0:1", 6), "2001::1")
        self.assertTrue(common.canonicalise_ip("abcd:eff::", 6), "abcd:eff::")
        self.assertTrue(common.canonicalise_ip("abcd:0000:eff::", 6),
                        "abcd:0:eff::")
        self.assertTrue(common.canonicalise_ip("::", 6), "::")

