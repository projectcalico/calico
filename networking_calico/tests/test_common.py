# -*- coding: utf-8 -*-
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
import unittest

from networking_calico.common import config


class TestConfig(unittest.TestCase):

    def test_additional_options_registered(self):
        add_opt = cfg.StrOpt('test_option', default='test')
        config.register_options(cfg.CONF, additional_options=[add_opt])
        self.assertEqual(cfg.CONF['calico']['test_option'], 'test')


from collections import namedtuple
import copy
import logging
import mock
import re


import networking_calico.common as common
from networking_calico.common import ValidationFailed

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

        # No rules.
        prof = {}
        common.validate_profile("prof1", prof)
        self.assertEqual(prof, {"inbound_rules": [], "outbound_rules": []})

        rules = {'inbound_rules': 3,
                 'outbound_rules': []}
        with self.assertRaisesRegexp(
                ValidationFailed,
                "Expected rules\[inbound_rules\] to be a list"
        ):
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
        with self.assertRaisesRegexp(
                ValidationFailed,
                "Calico/OpenStack is not expected to generate profiles " +
                "that use selectors"
        ):
            common.validate_profile(profile_id, rules)

        rule = {'dst_selector': "+b"}
        rules = {'inbound_rules': [rule],
                 'outbound_rules': []}
        with self.assertRaisesRegexp(
                ValidationFailed,
                "Calico/OpenStack is not expected to generate profiles " +
                "that use selectors"
        ):
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


class _BaseRuleTests(unittest.TestCase):
    """Base class for testing rule validation.

    Has subclasses for negated and non-negated matches.

    The negated match subclass pre-processes the rules before passing them
    to the validation function to negate the keys.
    """
    neg_pfx = None

    def add_neg_pfx(self, rule, exclude_keys=None):
        """Prepends the negation prefix to the relevant rule keys."""
        exclude_keys = exclude_keys or set()
        rule2 = dict([(self.neg_pfx + k if
                       (k in common.NEGATABLE_MATCH_KEYS and
                        k not in exclude_keys)
                      else k, v) for (k, v) in rule.iteritems()])
        assert len(rule) == len(rule2)
        return rule2

    def assert_rule_valid(self, rule, exp_updated_rule=None,
                          exclude_keys=None):
        """Asserts that a rule passes validation.

        :param rule: Rule to validate.
        :param exp_updated_rule: Expected canonical version of the rule, after
               validation.
        :param exclude_keys: Set of keys to exclude from negation.
        """
        if exp_updated_rule is None:
            exp_updated_rule = copy.deepcopy(rule)
        rule = self.add_neg_pfx(rule, exclude_keys=exclude_keys)
        exp_updated_rule = self.add_neg_pfx(exp_updated_rule,
                                            exclude_keys=exclude_keys)

        rule_copy = copy.deepcopy(rule)
        issues = []
        common._validate_rules({"inbound_rules": [rule_copy],
                                "outbound_rules": []}, issues)
        self.assertFalse(issues, "Rule should have no issues, got %s" % issues)
        self.assertEqual(rule_copy, exp_updated_rule)

        rule_copy = copy.deepcopy(rule)
        common._validate_rules({"inbound_rules": [],
                                "outbound_rules": [rule_copy]}, issues)
        self.assertFalse(issues, "Rule should have no issues (outbound), "
                                 "got %s" % issues)
        self.assertEqual(rule_copy, exp_updated_rule)

    def assert_rule_issue(self, rule, exp_issue_re, exclude_keys=None):
        """assert_rule_issue

        Asserts that a rule fails validation with an issue matching
        the regex.
        :param rule: The rule to validate.
        :param str exp_issue_re: Regex to match the issues against.
        :param exclude_keys: set of keys to exclude from negation.
        """
        rule = self.add_neg_pfx(rule, exclude_keys=exclude_keys)
        issues = []
        common._validate_rules({"inbound_rules": [rule],
                                "outbound_rules": []}, issues)
        self.assertTrue(issues, "Rule should have had issues")
        for issue in issues:
            if re.match(exp_issue_re, issue):
                break
        else:
            self.fail("No issue in %s matched regex %s" %
                      (issues, exp_issue_re))

    def test_protocol(self):
        self.assert_rule_valid({"protocol": "tcp"})
        self.assert_rule_valid({"protocol": "udp"})
        self.assert_rule_valid({"protocol": "udplite"})
        self.assert_rule_valid({"protocol": "sctp"})
        self.assert_rule_valid({"protocol": "icmp"})
        self.assert_rule_valid({"protocol": "icmpv6"})
        self.assert_rule_valid({"protocol": "42"},)
        # numbers get normalised to str.
        self.assert_rule_valid({"protocol": 33}, {"protocol": "33"})

        self.assert_rule_issue({"protocol": "abcd"},
                               "Invalid !?protocol abcd in rule")

    def test_tag(self):
        self.assert_rule_valid({"src_tag": "foo"})
        self.assert_rule_valid({"dst_tag": "foo"})

        self.assert_rule_issue({"src_tag": "+"}, "Invalid !?src_tag")
        self.assert_rule_issue({"dst_tag": "+"}, "Invalid !?dst_tag")

    def test_nets(self):
        self.assert_rule_valid(
            {"src_net": "10/8",
             "dst_net": "11/8"},
            {"src_net": "10.0.0.0/8",
             "dst_net": "11.0.0.0/8"}
        )

        self.assert_rule_issue({"src_net": "fhaedfh"}, "Invalid CIDR")
        self.assert_rule_issue({"dst_net": "fhaedfh"}, "Invalid CIDR")

    def test_ports(self):
        for key in ["src_ports", "dst_ports"]:
            for proto in ["tcp", "udp", "udplite", "sctp"]:
                self.assert_rule_valid({"protocol": proto,
                                        key: [1, "2:3"]},
                                       exclude_keys=set(["protocol"]))
                self.assert_rule_issue({"protocol": proto,
                                        key: {}},
                                       "Expected ports to be a list",
                                       exclude_keys=set(["protocol"]))
                self.assert_rule_issue({"protocol": "icmp",
                                        key: [1]},
                                       "!?%s is not allowed for "
                                       "protocol icmp" % key,
                                       exclude_keys=set(["protocol"]))
                self.assert_rule_issue({"protocol": proto,
                                        key: ["foo"]},
                                       "Invalid port",
                                       exclude_keys=set(["protocol"]))

    def test_icmp_type(self):
        self.assert_rule_valid({"icmp_type": 123})
        self.assert_rule_valid({"icmp_type": 123, "icmp_code": 10})
        self.assert_rule_issue({"icmp_type": "123"},
                               "ICMP type is not an integer")
        self.assert_rule_issue({"icmp_type": -1},
                               "ICMP type is out of range")
        self.assert_rule_issue({"icmp_type": 256},
                               "ICMP type is out of range")
        self.assert_rule_issue({"icmp_type": 100, "icmp_code": -1},
                               "ICMP code is out of range")
        self.assert_rule_issue({"icmp_type": 100, "icmp_code": 256},
                               "ICMP code is out of range")
        self.assert_rule_issue({"icmp_type": 100, "icmp_code": "256"},
                               "ICMP code is not an integer")
        self.assert_rule_issue({"icmp_code": 123},
                               "ICMP code specified without ICMP type")

    def test_action(self):
        self.assert_rule_valid({"action": "allow"})
        self.assert_rule_valid({"action": "deny"})
        self.assert_rule_valid({"action": "next-tier"})
        self.assert_rule_issue({"action": "foobar"}, "Invalid action")


class TestPositiveMatchCriteria(_BaseRuleTests):
    neg_pfx = ""


class TestNegativeMatchCriteria(_BaseRuleTests):
    neg_pfx = "!"

    def test_add_prefix(self):
        self.assertEqual(self.add_neg_pfx({"src_tag": "abcd",
                                           "protocol": "foo"},
                                          exclude_keys=set(["protocol"])),
                         {"!src_tag": "abcd", "protocol": "foo"})


# Prevent test infrastructure from thinking that it should run the
# _BaseRuleTests class in its own right.
del _BaseRuleTests
