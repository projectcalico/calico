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
felix.test.test_fiptables
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables handling function.
"""

import logging
from calico.felix import fiptables
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


EXTRACT_UNREF_TESTS = [
("""Chain INPUT (policy DROP)
target     prot opt source               destination
felix-INPUT  all  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:domain

Chain FORWARD (policy DROP)
target     prot opt source               destination
felix-FORWARD  all  --  anywhere             anywhere
ufw-track-forward  all  --  anywhere             anywhere

Chain DOCKER (1 references)
target     prot opt source               destination

Chain felix-FORWARD (1 references)
target     prot opt source               destination
felix-FROM-ENDPOINT  all  --  anywhere             anywhere
felix-TO-ENDPOINT  all  --  anywhere             anywhere
Chain-with-bad-name   all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere

Chain felix-temp (0 references)
target     prot opt source               destination
felix-FROM-ENDPOINT  all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
""",
set(["felix-temp"])),
]


class TestIptablesUpdater(BaseTestCase):

    def test_extract_unreffed_chains(self):
        for inp, exp in EXTRACT_UNREF_TESTS:
            output = fiptables._extract_our_unreffed_chains(inp)
            self.assertEqual(exp, output, "Expected\n\n%s\n\nTo parse as: %s\n"
                                          "but got: %s" % (inp, exp, output))