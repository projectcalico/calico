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
import unittest
from netaddr import IPNetwork
from calico_cni import policy_parser
from nose.tools import assert_equal, assert_raises
from nose_parameterized import parameterized
from netaddr import AddrFormatError


class PolicyParserTest(unittest.TestCase):

    def setUp(self):
        self.namespace = "testNamespace"
        self.parser = policy_parser.PolicyParser(self.namespace)

    def test_parse_basic_rule(self):
        rule = "allow from cidr 172.24.114.0/24 to cidr 1.2.3.4"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['src_net'], IPNetwork("172.24.114.0/24"))
        assert_equal(parsed['dst_net'], IPNetwork("1.2.3.4/32"))

        rule = "allow from label A=B"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        expected_tag = "%s_A_B" % self.namespace
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['src_tag'], expected_tag)

    def test_parse_allow(self):
        rule = "allow"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed.get('protocol'), None)
        assert_equal(parsed.get('src_ports'), None)
        assert_equal(parsed.get('dst_ports'), None)
        assert_equal(parsed.get('src_tag'), None)
        assert_equal(parsed.get('dst_tag'), None)
        assert_equal(parsed.get('icmp_type'), None)
        assert_equal(parsed.get('icmp_code'), None)

    def test_parse_udp_rule(self):
        rule = "allow udp from ports 443 cidr 1.2.3.4/32 to ports 80,90,100"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # assert on the result
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "udp")
        assert_equal(parsed['src_ports'], ['443'])
        assert_equal(parsed['src_net'], IPNetwork("1.2.3.4/32"))
        assert_equal(parsed['dst_ports'], ['80', '90', '100'])

        # Again
        rule = "allow udp to cidr 1.2.0.0/16"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "udp")
        assert_equal(parsed['dst_net'], IPNetwork("1.2.0.0/16"))

    def test_parse_tcp_rule(self):
        rule = "allow tcp from label test=label to ports 80,90,100"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        expected_tag = "%s_test_label" % self.namespace
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "tcp")
        assert_equal(parsed['src_tag'], expected_tag)
        assert_equal(parsed['dst_ports'], ['80', '90', '100'])

        # Try again with a destination label.
        rule = "allow tcp to ports 80,90,100 label test=label"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        expected_tag = "%s_test_label" % self.namespace
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "tcp")
        assert_equal(parsed['dst_tag'], expected_tag)
        assert_equal(parsed['dst_ports'], ['80', '90', '100'])

    def test_parse_icmp_rule(self):
        rule = "allow icmp type 8 code 2 from label A=B to cidr 1.2.0.0/16"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        expected_tag = "%s_A_B" % self.namespace
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "icmp")
        assert_equal(parsed['icmp_type'], '8')
        assert_equal(parsed['icmp_code'], '2')
        assert_equal(parsed['src_tag'], expected_tag)
        assert_equal(parsed['dst_net'], IPNetwork("1.2.0.0/16"))

        rule = "allow icmp type 8 from cidr 1.2.0.0/16"

        # Parse the rule
        parsed = self.parser.parse_line(rule)

        # Assert on the result
        assert_equal(parsed['action'], "allow")
        assert_equal(parsed['protocol'], "icmp")
        assert_equal(parsed['icmp_type'], '8')
        assert_equal(parsed['src_net'], IPNetwork("1.2.0.0/16"))

    @parameterized.expand([
        ("allow icmp type code 4"),
        ("allow icmp type ten code 4"),
        ("allow tcp from label test_label to ports 80,90,100"),
        ("allow tcp from udp ports 80,90,100"),
        ("reject tcp from ports 1"),
        ("allow udp to ports 80 from label A=B"),
        ("allow udp to ports 80,Y,100"),
        (""),
        ("allow lldp from label A=B"),
        ("allow from label"),
        ("allow from cidr"),
        ("allow from tag testtag"),
    ])
    def test_parse_errors(self, rule):
        """Test invalid policy statements"""
        # Use tag instead of label
        assert_raises(ValueError, self.parser.parse_line, rule)

    def test_parse_cidr_error(self):
        """Test invalid cidr policy statement"""
        assert_raises(AddrFormatError, self.parser.parse_line,
                      "allow from cidr 172.24.500.1")

    @parameterized.expand([
        ("some=invalid=label"),
        ("invalid=char!"),
        ("te$t=.*gex"),
        ("=another"),
        ("missing="),
    ])
    def test_validate_label_failed(self, label):
        """Test invalid label validation"""
        # Each should raise a ValueError
        assert_raises(ValueError, self.parser._validate_label, label)
