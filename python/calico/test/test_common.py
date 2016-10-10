# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
# Copyright 2015 Cisco Systems
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
import re
from collections import namedtuple
import logging
import mock
import sys

from nose.tools import assert_raises
from unittest2 import skip

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


import calico.common as common
from calico.common import ValidationFailed
from calico.datamodel_v1 import WloadEndpointId, TieredPolicyId, HostEndpointId

Config = namedtuple("Config", ["IFACE_PREFIX", "HOSTNAME"])

# Logger
_log = logging.getLogger(__name__)


MISSING = object()


class TestCommon(unittest.TestCase):
    def setUp(self):
        self.m_config = mock.Mock()
        self.m_config.IFACE_PREFIX = ["tap"]
        self.m_config.HOSTNAME = "localhost"

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

    def test_validate_rules_canon(self):
        rules = {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10/8",
                 "dst_net": "11.0/16", "src_ports": [10, "11:12"],
                 "action": "allow",
                 "log_prefix": "foo!@#$012345678901234567890123456789"},
                {"action": "log"},
                {"protocol": "tcp", "src_net": None},
            ],
            "outbound_rules": [
                {"protocol": "tcp", "ip_version": 6,
                 "src_net": "2001:0::1/128", "dst_net": "2001:0::/64",
                 "icmp_type": 7, "icmp_code": 10,
                 "action": "deny"}
            ],
        }
        common.validate_profile("profile_id", rules)
        # Check IPs get made canonical.
        self.assertEqual(rules, {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10.0.0.0/8",
                 "dst_net": "11.0.0.0/16", "src_ports": [10, "11:12"],
                 "action": "allow",
                 "log_prefix": "foo____01234567890123456789"},
                {"action": "log"},
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

        self.assertIsNone(common.canonicalise_ip(None, 4))
        self.assertIsNone(common.canonicalise_ip(None, 6))

    def test_validate_tier_data(self):
        good_data = {"order": 10}
        common.validate_tier_data("abcd_-ef", good_data)
        with self.assertRaises(ValidationFailed):
            # Bad name
            common.validate_tier_data("", good_data)
        with self.assertRaises(ValidationFailed):
            # Bad name
            common.validate_tier_data("+|$", good_data)
        with self.assertRaises(ValidationFailed):
            # Bad order value
            common.validate_tier_data("abc", {"order": "10"})
        with self.assertRaises(ValidationFailed):
            # Non-dict.
            common.validate_tier_data("abc", "foo")
        # Missing order.
        tier = {}
        common.validate_tier_data("abc", tier)
        self.assertEqual(tier["order"], common.INFINITY)
        self.assertGreater(tier["order"], 999999999999999999999999999999999999)
        # "default" order.
        tier = {"order": "default"}
        common.validate_tier_data("abc", tier)
        self.assertEqual(tier["order"], common.INFINITY)
        self.assertGreater(tier["order"], 999999999999999999999999999999999999)

    @skip("golang rewrite")
    def test_validate_rules(self):
        profile_id = "valid_name-ok."
        rules = {'inbound_rules': [],
                 'outbound_rules': []}
        common.validate_profile(profile_id, rules.copy())

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected profile 'valid_name-ok.' to "
                                     "be a dict"):
            common.validate_profile(profile_id, [])

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid profile ID"):
            common.validate_profile("a&b", rules.copy())
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid profile ID"):
            common.y(TieredPolicyId("+123", "abc"),
                                   rules.copy())
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid profile ID"):
            common.y(TieredPolicyId("abc", "+"),
                                   rules.copy())

        # No rules.
        prof = {}
        common.validate_profile("prof1", prof)
        self.assertEqual(prof, {"inbound_rules": [], "outbound_rules": []})

        rules = {'inbound_rules': 3,
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                            "Expected rules\[inbound_rules\] to be a list"):
            common.validate_profile(profile_id, rules.copy())

        rule = "not a dict"
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Rule should be a dict"):
            common.validate_profile(profile_id, rules.copy())

        rule = {'bad_key': ""}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Rule contains unknown keys"):
            common.validate_profile(profile_id, rules)

        rule = {'protocol': "bloop"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid protocol bloop in rule "
                                     "{'protocol': 'bloop'}"):
            common.validate_profile(profile_id, rules)

        rule = {'ip_version': 5}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid ip_version in rule"):
            common.validate_profile(profile_id, rules)

        rule = {'ip_version': 4,
                'protocol': "icmpv6"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Using icmpv6 with IPv4"):
            common.validate_profile(profile_id, rules)

        rule = {'ip_version': 6,
                'protocol': "icmp"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Using icmp with IPv6"):
            common.validate_profile(profile_id, rules)

        rule = {'src_tag': "abc",
                'protocol': "icmp"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        common.validate_profile(profile_id, rules)

        rule = {'src_tag': "abc",
                'protocol': "123"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        common.validate_profile(profile_id, rules)

        rule = {'protocol': "256"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid protocol 256 in rule"):
            common.validate_profile(profile_id, rules)

        rule = {'protocol': "0"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid protocol 0 in rule"):
            common.validate_profile(profile_id, rules)

        rule = {'src_tag': "a!b",
                'protocol': "icmp"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid src_tag"):
            common.validate_profile(profile_id, rules)

        rule = {'dst_tag': "x,y",
                'protocol': "icmp"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid dst_tag"):
            common.validate_profile(profile_id, rules)

        rule = {'src_selector': "a!b"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid src_selector"):
            common.validate_profile(profile_id, rules)

        rule = {'dst_selector': "+b"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid dst_selector"):
            common.validate_profile(profile_id, rules)

        rule = {'src_net': "nonsense"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid CIDR"):
            common.validate_profile(profile_id, rules)

        rule = {'dst_net': "1.2.3.4/16",
                'ip_version': 6}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid CIDR"):
            common.validate_profile(profile_id, rules)

        rule = {'src_ports': "nonsense"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected ports to be a list"):
            common.validate_profile(profile_id, rules)

        rule = {'dst_ports': [32, "nonsense"]}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid port"):
            common.validate_profile(profile_id, rules)

        rule = {'action': "nonsense"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid action"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': "nonsense"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP type is not an integer"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': -1}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP type is out of range"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': 256}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP type is out of range"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': 22,
                'icmp_code': "2"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP code is not an integer"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': 0,
                'icmp_code': -1}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP code is out of range"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_type': 0,
                'icmp_code': 256}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP code is out of range"):
            common.validate_profile(profile_id, rules)

        rule = {'icmp_code': 2}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "ICMP code specified without ICMP type"):
            common.validate_profile(profile_id, rules)

        rule = {'log_prefix': []}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Log prefix should be a string"):
            common.validate_profile(profile_id, rules)

    @skip("golang rewrite")
    def test_validate_policy(self):
        policy_id = TieredPolicyId("a", "b")
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected policy 'a/b' to "
                                     "be a dict"):
            common.validate_policy(policy_id, [])

        rules = {'selector': "+abcd", # Bad selector
                 'inbound_rules': [],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Failed to parse selector"):
            common.validate_policy(policy_id, rules)

    @skip("golang rewrite")
    def test_validate_order(self):
        policy = {
            "selector": "a == 'b'",
            "order": 10,
            "inbound_rules": [],
            "outbound_rules": [],
        }
        common.validate_policy(TieredPolicyId("a", "b"), policy)

        policy = {
            "selector": "a == 'b'",
            "order": "10",
            "inbound_rules": [],
            "outbound_rules": [],
        }
        with self.assertRaises(ValidationFailed):
            common.validate_policy(TieredPolicyId("a", "b"), policy)

        policy = {
            "selector": "a == 'b'",
            "inbound_rules": [],
            "outbound_rules": [],
        }
        common.validate_policy(TieredPolicyId("a", "b"), policy)
        self.assertEqual(policy["order"], common.INFINITY)
        self.assertGreater(policy["order"], 9999999999999999999999999999999999)

        policy = {
            "selector": "a == 'b'",
            "inbound_rules": [],
            "outbound_rules": [],
            "order": "default",
        }
        common.validate_policy(TieredPolicyId("a", "b"), policy)
        self.assertEqual(policy["order"], common.INFINITY)
        self.assertGreater(policy["order"], 9999999999999999999999999999999999)

        policy = {
            "order": 10,
            "inbound_rules": [],
            "outbound_rules": [],
        }
        with self.assertRaises(ValidationFailed):
            common.validate_policy(TieredPolicyId("a", "b"), policy)

    def test_validate_rule_port(self):
        self.assertEqual(common.validate_rule_port(73), None)
        self.assertEqual(common.validate_rule_port("57:123"), None)
        self.assertEqual(common.validate_rule_port("0:1024"), None)
        self.assertEqual(common.validate_rule_port(0), None)
        self.assertEqual(common.validate_rule_port(65536),
                         "integer out of range")
        self.assertEqual(common.validate_rule_port([]),
                         "neither integer nor string")
        self.assertEqual(common.validate_rule_port("1:2:3"),
                         "range unparseable")
        self.assertEqual(common.validate_rule_port("1"),
                         "range unparseable")
        self.assertEqual(common.validate_rule_port(""),
                         "range unparseable")
        self.assertEqual(common.validate_rule_port("a:b"),
                         "range invalid")
        self.assertEqual(common.validate_rule_port("3:1"),
                         "range invalid")
        self.assertEqual(common.validate_rule_port("-1:3"),
                         "range invalid")
        self.assertEqual(common.validate_rule_port("5:65536"),
                         "range invalid")

    def test_validate_tags(self):
        profile_id = "valid_name-ok."
        tags = [ "name", "_name-with.chars.-_" ]
        common.validate_tags(profile_id, tags)

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid profile"):
            common.validate_tags('bad"value', tags)

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected tags to be a list"):
            common.validate_tags(profile_id, "not a list")

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected tag.* to be a string"):
            common.validate_tags(profile_id, ["value", 3])

        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid tag"):
            common.validate_tags(profile_id, ["value", "bad value"])

    def test_validate_ipam_pool(self):
        self.assert_ipam_pool_valid({"cidr": "10/16", "foo": "bar"},
                                    {"cidr": "10.0.0.0/16"}, 4)
        self.assert_ipam_pool_valid({"cidr": "1234:0::/64"},
                                    {"cidr": "1234::/64"}, 6)
        self.assert_ipam_pool_invalid({"cidr": None}, 4)
        self.assert_ipam_pool_invalid({"cidr": "10/16"}, 4, pool_id="nonsense")
        self.assert_ipam_pool_invalid({}, 6)
        self.assert_ipam_pool_invalid({"cidr": "10.0.0.0/16",
                                       "masquerade": "foo"}, 4)
        self.assert_ipam_pool_invalid(None, 4)
        self.assert_ipam_pool_invalid([], 4)

    def assert_ipam_pool_valid(self, pool, expected, version,
                               pool_id="1234-5"):
        common.validate_ipam_pool(pool_id, pool, version)
        self.assertEqual(pool, expected)

    def assert_ipam_pool_invalid(self, pool, version, pool_id="1234-5"):
        self.assertRaises(ValidationFailed,
                          common.validate_ipam_pool, pool_id, pool, version)

    def test_labels_validation(self):
        common.validate_labels("prof_id", {"a": "b"})
        assert_raises(ValidationFailed,
                      common.validate_labels, "prof_id", {"a": ["b"]})
        assert_raises(ValidationFailed,
                      common.validate_labels, "prof_id", {"a": [1]})
        assert_raises(ValidationFailed,
                      common.validate_labels, "prof_id", {"a": [None]})
        assert_raises(ValidationFailed,
                      common.validate_labels, "prof_id", {"a": None})
        assert_raises(ValidationFailed,
                      common.validate_labels, "prof_id", {"a": 1})
        assert_raises(ValidationFailed,
                      common.validate_labels, "+", {"a": "b"})


class _BaseTestValidateEndpoint(unittest.TestCase):
    validate_endpoint = None
    use_fip_by_default = True

    def setUp(self):
        self.m_config = mock.Mock()
        self.m_config.IFACE_PREFIX = ["tap"]
        self.m_config.HOSTNAME = "localhost"

    def create_id(self):
        raise NotImplementedError()

    def valid_endpoint(self, **kwargs):
        raise NotImplementedError()
    
    def canonical_valid_endpoint(self, **kwargs):
        raise NotImplementedError()

    def do_canonicalisation_test(self, **kwargs):
        endpoint = self.valid_endpoint(**kwargs)
        self.validate_endpoint(self.m_config, self.create_id(), endpoint)
        self.assertEqual(endpoint, self.canonical_valid_endpoint(**kwargs))

    def test_validate_endpoint_canonicalises(self):
        self.do_canonicalisation_test()

    def test_validate_endpoint_mainline_profile_ids(self):
        self.do_canonicalisation_test(use_prof_ids=True)

    def test_validate_endpoint_mainline_profile_ids_missing(self):
        self.do_canonicalisation_test(use_prof_ids=MISSING)

    def test_validate_endpoint_failures_common(self):
        self.assert_invalid_endpoint([])
        self.assert_invalid_endpoint("foo")
        self.assert_invalid_endpoint(1234)

    def assert_invalid_endpoint(self, bad_value):
        self.assertRaises(common.ValidationFailed, self.validate_endpoint,
                          self.m_config, self.create_id(), bad_value)

    def assert_endpoint_valid(self, original_endpoint):
        endpoint = copy.deepcopy(original_endpoint)
        try:
            # First pass at validation, may canonicalise the data.
            self.validate_endpoint(self.m_config, self.create_id(), endpoint)
            canonical_endpoint = copy.deepcopy(endpoint)
            # Second pass, should make no changes.
            self.validate_endpoint(self.m_config, self.create_id(),
                                   canonical_endpoint)
            self.assertEqual(endpoint, canonical_endpoint)
        except common.ValidationFailed as e:
            _log.exception("Validation unexpectedly failed for %s",
                           original_endpoint)
            self.fail("Validation unexpectedly failed for %s: %r" %
                      (original_endpoint, e))

    def assert_tweak_invalidates_endpoint(self, **tweak):
        use_prof_ids = "profile_id" not in tweak
        valid_endpoint = self.valid_endpoint(use_prof_ids=use_prof_ids,
                                             use_fip=self.use_fip_by_default)
        self.assert_endpoint_valid(valid_endpoint)
        invalid_endpoint = valid_endpoint.copy()
        for key, value in tweak.iteritems():
            if value is MISSING:
                invalid_endpoint.pop(key)
            else:
                invalid_endpoint[key] = value
        self.assert_invalid_endpoint(invalid_endpoint)


class TestValidateWloadEndpoint(_BaseTestValidateEndpoint):
    def validate_endpoint(self, *args, **kwargs):
        common.validate_endpoint(*args, **kwargs)

    def create_id(self):
        return WloadEndpointId("localhost", "orchestrator",
                               "workload", "endpoint")

    def valid_endpoint(self, use_fip=False, use_prof_ids=False):
        ep = {
            "state": "active",
            "name": "tap1234",
            "mac": "AA:bb:cc:dd:ee:ff",
            "ipv4_nets": ["10.0.1/32"],
            "ipv4_gateway": "11.0.0.1",
            "ipv6_nets": ["2001:0::1/128"],
            "ipv6_gateway": "fe80:0::1",
        }
        if use_prof_ids == MISSING:
            pass
        elif use_prof_ids:
            ep["profile_ids"] = ["prof1", "prof2"]
        else:
            ep["profile_id"] = "prof1"
        if use_fip:
            ep.update({
                "ipv4_nat": [{"int_ip": "10.0.1.0", "ext_ip": "192.168.1"}],
                "ipv6_nat": [{"int_ip": "2001::1", "ext_ip": "2001::2"}],
            })
        return ep

    def canonical_valid_endpoint(self, use_fip=False, use_prof_ids=False):
        ep = {
            'state': 'active',
            'name': 'tap1234',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ipv4_nets': ['10.0.1.0/32'],
            'ipv4_gateway': '11.0.0.1',
            'ipv6_nets': ['2001::1/128'],
            'ipv6_gateway': 'fe80::1',
        }
        if use_prof_ids == MISSING:
            ep["profile_ids"] = []
        elif use_prof_ids:
            ep["profile_ids"] = ["prof1", "prof2"]
        else:
            ep["profile_ids"] = ["prof1"]  # Normalised to a list.
        if use_fip:
            ep.update({
                "ipv4_nat": [{"int_ip": "10.0.1.0", "ext_ip": "192.168.0.1"}],
                'ipv6_nat': [{'int_ip': '2001::1', 'ext_ip': '2001::2'}],
            })
        return ep

    def test_validate_endpoint_mainline_fip(self):
        self.do_canonicalisation_test(use_fip=True)

    def test_validate_endpoint_failures(self):
        self.assert_tweak_invalidates_endpoint(state=MISSING)
        self.assert_tweak_invalidates_endpoint(state=None)
        self.assert_tweak_invalidates_endpoint(state="foo")

        self.assert_tweak_invalidates_endpoint(name=MISSING)
        self.assert_tweak_invalidates_endpoint(name=None)
        self.assert_tweak_invalidates_endpoint(name="")
        self.assert_tweak_invalidates_endpoint(name=object())
        self.assert_tweak_invalidates_endpoint(name=[])
        self.assert_tweak_invalidates_endpoint(name="incorrect_prefix")

        self.assert_tweak_invalidates_endpoint(mac=object())
        self.assert_tweak_invalidates_endpoint(mac="bad MAC")

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

        self.assert_tweak_invalidates_endpoint(
            expected_ipv4_addrs=["10.0.0.1"])
        self.assert_tweak_invalidates_endpoint(expected_ipv4_addrs={})
        self.assert_tweak_invalidates_endpoint(
            expected_ipv6_addrs=["10.0.0.1"])
        self.assert_tweak_invalidates_endpoint(expected_ipv6_addrs={})

        self.assert_tweak_invalidates_endpoint(ipv4_nets=["10.1.2.3/32"],
                                               ipv4_nat=[{"int_ip": "10.1.2.4",
                                                          "ext_ip": "1.2.3.4"}])

    def test_validate_endpoint(self):
        # This test method hit s afew cases that we don't hit above but it's
        # hard to understand.  Please don't add more tests like this!
        combined_id = WloadEndpointId("host", "orchestrator",
                                      "workload", "valid_name-ok.")
        endpoint_dict = {'profile_id': "valid.prof-name",
                         'state': "active",
                         'name': "tapabcdef",
                         'mac': "78:2b:cb:9f:ae:1c",
                         'ipv4_nets': [],
                         'ipv6_nets': []}
        config = Config('tap', 'localhost')
        ep_copy = endpoint_dict.copy()
        self.validate_endpoint(config, combined_id, ep_copy)
        self.assertTrue(ep_copy.get('profile_id') is None)
        self.assertEqual(ep_copy.get('profile_ids'), ["valid.prof-name"])

        # Now break it various ways.
        # Bad endpoint ID.
        for bad_str in ("with spaces", "$stuff", "^%@"):
            bad_id = WloadEndpointId("host", "orchestrator", "workload",
                                     bad_str)
            with self.assertRaisesRegexp(ValidationFailed,
                                         "Invalid endpoint ID"):
                self.validate_endpoint(config, bad_id,
                                         endpoint_dict.copy())

        # Bad dictionary.
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected endpoint to be a dict"):
            self.validate_endpoint(config, combined_id, [1, 2, 3])

        # No state, invalid state.
        bad_dict = endpoint_dict.copy()
        del bad_dict['state']
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Missing 'state' field"):
            self.validate_endpoint(config, combined_id, bad_dict)
        bad_dict['state'] = "invalid"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected 'state' to be"):
            self.validate_endpoint(config, combined_id, bad_dict)

        # Missing name.
        bad_dict = endpoint_dict.copy()
        del bad_dict['name']
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Missing 'name' field"):
            self.validate_endpoint(config, combined_id, bad_dict)

        # It's OK to be missing a MAC.
        ok_dict = endpoint_dict.copy()
        del ok_dict['mac']
        self.validate_endpoint(config, combined_id, ok_dict)

        bad_dict['name'] = [1, 2, 3]
        bad_dict['mac'] = 73
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected 'name' to be a string.*" +
                                             "Invalid MAC"):
            self.validate_endpoint(config, combined_id, bad_dict)

        # Bad profile ID
        bad_dict = endpoint_dict.copy()
        bad_dict['profile_id'] = "str£ing"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid profile ID"):
            self.validate_endpoint(config, combined_id, bad_dict)

        bad_dict = endpoint_dict.copy()
        del bad_dict['profile_id']
        bad_dict['profile_ids'] = [1, 2, 3]
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected profile IDs to be strings"):
            self.validate_endpoint(config, combined_id, bad_dict)

        # Bad interface name - acceptable if not local.
        bad_dict = endpoint_dict.copy()
        bad_dict['name'] = "vethabcdef"
        self.validate_endpoint(config, combined_id, bad_dict)

        local_id = WloadEndpointId("localhost", "orchestrator",
                                   "workload", "valid_name-ok.")
        with self.assertRaisesRegexp(ValidationFailed,
                                     "does not start with"):
            self.validate_endpoint(config, local_id, bad_dict)

        # Valid networks.
        good_dict = endpoint_dict.copy()
        good_dict['ipv4_nets'] = ["1.2.3.4/32", "172.0.0.0/8", "3.4.5.6"]
        good_dict['ipv6_nets'] = ["::1/128", "::",
                                  "2001:db8:abc:1400::/54"]
        self.validate_endpoint(config, combined_id, good_dict.copy())

        # Invalid networks
        bad_dict = good_dict.copy()
        bad_dict['ipv4_nets'] = ["1.2.3.4/32", "172.0.0.0/8",
                                 "2001:db8:abc:1400::/54"]
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv4 CIDR"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        bad_dict['ipv4_nets'] = ["1.2.3.4/32", "172.0.0.0/8", "nonsense"]
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv4 CIDR"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())

        bad_dict = good_dict.copy()
        bad_dict['ipv6_nets'] = ["::1/128", "::", "1.2.3.4/8"]
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv6 CIDR"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        bad_dict['ipv6_nets'] = ["::1/128", "::", "nonsense"]
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv6 CIDR"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())

        # Gateway IPs.
        good_dict['ipv4_gateway'] = "1.2.3.4"
        good_dict['ipv6_gateway'] = "2001:db8:abc:1400::"
        self.validate_endpoint(config, combined_id, good_dict.copy())

        bad_dict = good_dict.copy()
        bad_dict['ipv4_gateway'] = "2001:db8:abc:1400::"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv4 gateway"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        bad_dict['ipv4_gateway'] = "nonsense"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv4 gateway"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())

        bad_dict = good_dict.copy()
        bad_dict['ipv6_gateway'] = "1.2.3.4"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv6 gateway"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        bad_dict['ipv6_gateway'] = "nonsense"
        with self.assertRaisesRegexp(ValidationFailed,
                                     "not a valid IPv6 gateway"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())

        # Labels, empty.
        good_dict["labels"] = {}
        self.validate_endpoint(config, combined_id, good_dict)
        self.assertEqual(good_dict["labels"], {})
        # Labels, valid.
        good_dict["labels"] = {"a": "b"}
        self.validate_endpoint(config, combined_id, good_dict)
        self.assertEqual(good_dict["labels"], {"a": "b"})
        # Labels, bad type.
        bad_dict = good_dict.copy()
        bad_dict["labels"] = []
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Expected labels to be a dict"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        # Labels, bad value.
        bad_dict = good_dict.copy()
        bad_dict["labels"] = {"a": {}}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid label value"):
            self.validate_endpoint(config, combined_id, bad_dict.copy())
        # Labels, bad key.
        bad_dict = good_dict.copy()
        bad_dict["labels"] = {"a+|%": {}}
        with self.assertRaisesRegexp(ValidationFailed,
                                     "Invalid label name 'a+|%'."):
            self.validate_endpoint(config, combined_id, bad_dict.copy())


class TestValidateHostEndpoint(_BaseTestValidateEndpoint):
    """Tests for host endpoint-specific validation."""
    use_fip_by_default = False

    def validate_endpoint(self, *args, **kwargs):
        common.validate_host_endpoint(*args, **kwargs)

    def create_id(self):
        return HostEndpointId("localhost", "endpoint")

    def valid_endpoint(self, use_fip=False, use_prof_ids=True,
                       use_exp_ips=True):
        ep = {
            "labels": {
                "a": "b",
                "c": "d",
            }
        }
        if use_exp_ips:
            ep["expected_ipv4_addrs"] = ["10.0.1", "1.2.3.4"]
            ep["expected_ipv6_addrs"] = ["2001:0::1"]
        else:
            # Note: name doesn't start with tap, which is OK.
            ep["name"] = "eth0"
        if use_prof_ids == MISSING:
            pass
        elif use_prof_ids:
            ep["profile_ids"] = ["prof1", "prof2"]
        else:
            ep["profile_id"] = "prof1"
        if use_fip:
            raise NotImplementedError()
        return ep

    def canonical_valid_endpoint(self, use_fip=False, use_prof_ids=True,
                                 use_exp_ips=True):
        ep = {
            "labels": {
                "a": "b",
                "c": "d",
            }
        }
        if use_exp_ips:
            ep["expected_ipv4_addrs"] = ["10.0.0.1", "1.2.3.4"]
            ep["expected_ipv6_addrs"] = ["2001::1"]
        else:
            ep["name"] = "eth0"
        if use_prof_ids == MISSING:
            ep["profile_ids"] = []
        elif use_prof_ids:
            ep["profile_ids"] = ["prof1", "prof2"]
        else:
            ep["profile_ids"] = ["prof1"]  # Normalised to a list.
        if use_fip:
            raise NotImplementedError()
        return ep

    def test_exp_ip_canon(self):
        self.do_canonicalisation_test(use_exp_ips=True)

    def test_no_exp_ip_canon(self):
        self.do_canonicalisation_test(use_exp_ips=False)

    def test_validate_endpoint_failures(self):
        self.assert_tweak_invalidates_endpoint(state="active")
        self.assert_tweak_invalidates_endpoint(state="inactive")
        self.assert_tweak_invalidates_endpoint(state=[])
        self.assert_tweak_invalidates_endpoint(mac="11:22:33:44:55:66")
        self.assert_tweak_invalidates_endpoint(mac="inactive")
        self.assert_tweak_invalidates_endpoint(mac=[])

        self.assert_tweak_invalidates_endpoint(ipv4_nets=[])
        self.assert_tweak_invalidates_endpoint(ipv4_nets=["10.0.0.1"])
        self.assert_tweak_invalidates_endpoint(ipv4_gateway=["10.0.0.1"])
        self.assert_tweak_invalidates_endpoint(ipv4_nat=[])
        self.assert_tweak_invalidates_endpoint(ipv6_nets=[])
        self.assert_tweak_invalidates_endpoint(ipv6_nets=["1002::1"])
        self.assert_tweak_invalidates_endpoint(ipv6_gateway=["1234::0"])
        self.assert_tweak_invalidates_endpoint(ipv6_nat=[])

        self.assert_tweak_invalidates_endpoint(expected_ipv4_addrs={})
        self.assert_tweak_invalidates_endpoint(expected_ipv4_addrs="10.0.0.1")
        self.assert_tweak_invalidates_endpoint(expected_ipv4_addrs=["10.0.Z"])
        self.assert_tweak_invalidates_endpoint(expected_ipv4_addrs=MISSING,
                                               expected_ipv6_addrs=MISSING)
        self.assert_tweak_invalidates_endpoint(expected_ipv6_addrs={})
        self.assert_tweak_invalidates_endpoint(expected_ipv6_addrs="10.0.0.1")
        self.assert_tweak_invalidates_endpoint(expected_ipv6_addrs=["10.0.Z"])

