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
felix.test.test_frules
~~~~~~~~~~~

Tests for fiptables. Much of this module is tested in test_felix, but this covers
some parts that are not.
"""
from copy import copy
import logging
import mock
import unittest

import calico.felix.frules as frules
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
import calico.felix.ipsets
import calico.felix.test.stub_ipsets as stub_ipsets

# Expected state
expected_ipsets = stub_ipsets.IpsetState()

# Logger
log = logging.getLogger(__name__)

class TestUpdateIpsets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Completely replace the ipsets modules.
        cls.real_ipsets = calico.felix.ipsets
        frules.ipsets = stub_ipsets

    @classmethod
    def tearDownClass(cls):
        # Reinstate the modules we overwrote
        frules.ipsets = cls.real_ipsets

    def setUp(self):
        stub_ipsets.reset()

        # Set the expected IP tables state to be clean.
        expected_ipsets.reset()

    def create_ipsets(self, family):
        stub_ipsets.create("ipset_port", "hash:net,port", family)
        stub_ipsets.create("ipset_addr", "hash:net", family)
        stub_ipsets.create("ipset_icmp", "hash:net", family)

        expected_ipsets.create("ipset_port", "hash:net,port", family)
        expected_ipsets.create("ipset_addr", "hash:net", family)
        expected_ipsets.create("ipset_icmp", "hash:net", family)

        stub_ipsets.create("tmp_ipset_port", "hash:net,port", family)
        stub_ipsets.create("tmp_ipset_addr", "hash:net", family)
        stub_ipsets.create("tmp_ipset_icmp", "hash:net", family)

        expected_ipsets.create("tmp_ipset_port", "hash:net,port", family)
        expected_ipsets.create("tmp_ipset_addr", "hash:net", family)
        expected_ipsets.create("tmp_ipset_icmp", "hash:net", family)


        if family == "inet":
            addr = "9.8.7.6/24"
        else:
            addr = "9:8:7::6/64"

        # Shove some junk into ipsets that will be tidied away.
        stub_ipsets.add("ipset_addr", addr)
        stub_ipsets.add("ipset_port", addr + ",tcp:123")
        stub_ipsets.add("ipset_icmp", addr)

    def tearDown(self):
        pass

    def test_empty_ipsets(self):
        """
        Empty ipsets.
        """
        description = "Description : blah"
        suffix = "whatever"
        rule_list = []

        self.create_ipsets("inet")

        frules.update_ipsets(IPV4,
                             description,
                             suffix,
                             rule_list,
                             "ipset_addr",
                             "ipset_port",
                             "ipset_icmp",
                             "tmp_ipset_addr",
                             "tmp_ipset_port",
                             "tmp_ipset_icmp")

        stub_ipsets.check_state(expected_ipsets)

    def test_ipv4_ipsets(self):
        """
        IPv4 ipsets
        """
        description = "description"
        suffix = "suffix"
        rule_list = []
        default_cidr = "1.2.3.4/24"

        self.create_ipsets("inet")

        # Ignored rules
        rule_list.append({ 'blah': "junk" }) # no CIDR
        rule_list.append({ 'cidr': "junk" }) # junk CIDR
        rule_list.append({ 'cidr': "::/64" }) # IPv6, not v4
        rule_list.append({ 'cidr': default_cidr,
                           'port': 123 }) # port, no protocol
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': "blah" }) # bad port
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': ["blah", "bloop"] }) # bad port range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [0, 123] }) # bad port in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [1, 2, 3] }) # not two in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [1] }) # not two in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "icmp",
                           'port': "1" }) # port not allowed
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "ipv6-icmp",
                           'port': "1" }) # port not allowed
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "icmp",
                           'icmp_code': "1" }) # code without type
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "blah",
                           'port': "1" }) # port not allowed for protocol

        # Better rules
        rule_list.append({ 'cidr': "1.2.3.4/24" })
        expected_ipsets.add("ipset_addr", "1.2.3.4/24")

        rule_list.append({ 'cidr': "10.0.10.0/0",
                           'protocol': "tcp"})
        expected_ipsets.add("ipset_port", "0.0.0.0/1,tcp:1-65535")
        expected_ipsets.add("ipset_port", "128.0.0.0/1,tcp:1-65535")

        rule_list.append({ 'cidr': "1.0.0.1/8",
                           'protocol': "udp",
                           'port': [2,10]})
        expected_ipsets.add("ipset_port", "1.0.0.1/8,udp:2-10")

        rule_list.append({ 'cidr': "1.0.0.2/8",
                           'protocol': "sctp",
                           'port': "2"})
        expected_ipsets.add("ipset_port", "1.0.0.2/8,sctp:2")

        rule_list.append({ 'cidr': "1.0.0.3/8",
                           'protocol': "udplite",
                           'port': [2,10]})
        expected_ipsets.add("ipset_port", "1.0.0.3/8,udplite:2-10")

        rule_list.append({ 'cidr': "1.0.0.4/8",
                           'protocol': "icmp" })
        expected_ipsets.add("ipset_icmp", "1.0.0.4/8")

        rule_list.append({ 'cidr': "1.0.0.5/8",
                           'protocol': "icmp",
                           'icmp_type': 123})
        expected_ipsets.add("ipset_port", "1.0.0.5/8,icmp:123/0")

        rule_list.append({ 'cidr': "1.0.0.6/8",
                           'protocol': "icmp",
                           'icmp_type': "type"})
        expected_ipsets.add("ipset_port", "1.0.0.6/8,icmp:type")

        rule_list.append({ 'cidr': "1.0.0.7/8",
                           'protocol': "icmp",
                           'icmp_type': 123,
                           'icmp_code': "code"})
        expected_ipsets.add("ipset_port", "1.0.0.7/8,icmp:123/code")

        rule_list.append({ 'cidr': "1.0.0.8/8",
                           'protocol': "icmp",
                           'icmp_type': "type",
                           'icmp_code': "code"}) # code ignored
        expected_ipsets.add("ipset_port", "1.0.0.8/8,icmp:type")

        rule_list.append({ 'cidr': "1.0.0.9/8",
                           'protocol': "blah" })
        expected_ipsets.add("ipset_port", "1.0.0.9/8,blah:0")

        frules.update_ipsets(IPV4,
                             description,
                             suffix,
                             rule_list,
                             "ipset_addr",
                             "ipset_port",
                             "ipset_icmp",
                             "tmp_ipset_addr",
                             "tmp_ipset_port",
                             "tmp_ipset_icmp")

        stub_ipsets.check_state(expected_ipsets)

    def test_ipv6_ipsets(self):
        """
        IPv6 ipsets
        """
        description = "description"
        suffix = "suffix"
        rule_list = []
        default_cidr = "2001::1:2:3:4/24"

        self.create_ipsets("inet6")

        # Ignored rules
        rule_list.append({ 'blah': "junk" }) # no CIDR
        rule_list.append({ 'cidr': "junk" }) # junk CIDR
        rule_list.append({ 'cidr': "1.2.3.4/32" }) # IPv4, not v6
        rule_list.append({ 'cidr': default_cidr,
                           'port': 123 }) # port, no protocol
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': "blah" }) # bad port
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': ["blah", "bloop"] }) # bad port range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [0, 123] }) # bad port in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [1, 2, 3] }) # not two in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "tcp",
                           'port': [1] }) # not two in range
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "icmp",
                           'port': "1" }) # port not allowed
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "ipv6-icmp",
                           'port': "1" }) # port not allowed
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "icmp",
                           'icmp_code': "1" }) # code without type
        rule_list.append({ 'cidr': default_cidr,
                           'protocol': "blah",
                           'port': "1" }) # port not allowed for protocol

        # Better rules
        rule_list.append({ 'cidr': "1:2:3::4/24" })
        expected_ipsets.add("ipset_addr", "1:2:3::4/24")

        rule_list.append({ 'cidr': "1:2:3::/0",
                           'protocol': "tcp"})
        expected_ipsets.add("ipset_port", "::/1,tcp:1-65535")
        expected_ipsets.add("ipset_port", "8000::/1,tcp:1-65535")

        rule_list.append({ 'cidr': "1::1/8",
                           'protocol': "udp",
                           'port': [2,10]})
        expected_ipsets.add("ipset_port", "1::1/8,udp:2-10")

        rule_list.append({ 'cidr': "1::2/8",
                           'protocol': "sctp",
                           'port': "2"})
        expected_ipsets.add("ipset_port", "1::2/8,sctp:2")

        rule_list.append({ 'cidr': "1::3/8",
                           'protocol': "udplite",
                           'port': [2,10]})
        expected_ipsets.add("ipset_port", "1::3/8,udplite:2-10")

        rule_list.append({ 'cidr': "1::4/8",
                           'protocol': "ipv6-icmp" })
        expected_ipsets.add("ipset_icmp", "1::4/8")

        rule_list.append({ 'cidr': "1::5/8",
                           'protocol': "ipv6-icmp",
                           'icmp_type': 123})
        expected_ipsets.add("ipset_port", "1::5/8,ipv6-icmp:123/0")

        rule_list.append({ 'cidr': "1::6/8",
                           'protocol': "ipv6-icmp",
                           'icmp_type': "type"})
        expected_ipsets.add("ipset_port", "1::6/8,ipv6-icmp:type")

        rule_list.append({ 'cidr': "1::7/8",
                           'protocol': "ipv6-icmp",
                           'icmp_type': 123,
                           'icmp_code': "code"})
        expected_ipsets.add("ipset_port", "1::7/8,ipv6-icmp:123/code")

        rule_list.append({ 'cidr': "1::8/8",
                           'protocol': "ipv6-icmp",
                           'icmp_type': "type",
                           'icmp_code': "code"}) # code ignored
        expected_ipsets.add("ipset_port", "1::8/8,ipv6-icmp:type")

        rule_list.append({ 'cidr': "1::9/8",
                           'protocol': "blah" })
        expected_ipsets.add("ipset_port", "1::9/8,blah:0")

        frules.update_ipsets(IPV6,
                             description,
                             suffix,
                             rule_list,
                             "ipset_addr",
                             "ipset_port",
                             "ipset_icmp",
                             "tmp_ipset_addr",
                             "tmp_ipset_port",
                             "tmp_ipset_icmp")

        stub_ipsets.check_state(expected_ipsets)

    def test_exception(self):
        """
        Test exception when adding ipset value.
        """
        description = "description"
        suffix = "suffix"
        rule_list = [{'cidr': "1.2.3.4/24"}]

        self.create_ipsets("inet")

        with mock.patch('calico.felix.test.stub_ipsets.add',
                        side_effect=FailedSystemCall("oops", [], 1, "", "")):
            frules.update_ipsets(IPV4,
                                 description,
                                 suffix,
                                 rule_list,
                                 "ipset_addr",
                                 "ipset_port",
                                 "ipset_icmp",
                                 "tmp_ipset_addr",
                                 "tmp_ipset_port",
                                 "tmp_ipset_icmp")

        stub_ipsets.check_state(expected_ipsets)
