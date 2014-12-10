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
felix.test.test_felix
~~~~~~~~~~~

Top level tests for Felix.
"""
import sys
import unittest
import time
import calico.felix.futils as futils

# Import our stub utils module which replaces time.
import calico.felix.test.stub_utils as stub_utils
futils.time_ms = stub_utils.get_time

# Replace zmq with our stub zmq.
import calico.felix.test.stub_zmq as stub_zmq
sys.modules['zmq'] = stub_zmq

# Hide iptc, since we do not have it.
sys.modules['iptc'] = __import__('calico.felix.test.stub_empty')

# Replace calico.felix.fiptables with calico.felix.test.stub_fiptables
import calico.felix.test.stub_fiptables
sys.modules['calico.felix.fiptables'] = __import__('calico.felix.test.stub_fiptables')
calico.felix.fiptables = calico.felix.test.stub_fiptables
stub_fiptables = calico.felix.test.stub_fiptables

# Now import felix, and away we go.
import calico.felix.felix as felix
import calico.common as common
from calico.felix.futils import IPV4, IPV6

# IPtables state.
expected_state = stub_fiptables.TableState()

# Default config path.
config_path = "calico/felix/test/data/felix_debug.cfg"

class TestBasic(unittest.TestCase):
    def setUp(self):
        stub_utils.set_time(0)
        stub_zmq.clear_poll_results()
        stub_fiptables.reset_current_state()
        expected_state.reset()

    def test_startup(self):
        common.default_logging()
        agent = felix.FelixAgent(config_path)
        set_global_rules()
        stub_fiptables.check_state(expected_state)

    def test_no_work(self):
        poll_result = stub_zmq.PollResult(0)

        common.default_logging()
        agent = felix.FelixAgent(config_path)
        agent.run()

        set_global_rules()
        stub_fiptables.check_state(expected_state)


def set_global_rules():
    """
    Sets up the minimal global rules we expect to have.
    """
    table = expected_state.tables_v4["filter"]
    chain = table.chains["FORWARD"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-FORWARD"))
    chain = table.chains["INPUT"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-INPUT"))
    stub_fiptables.get_chain(table, "felix-FORWARD")
    stub_fiptables.get_chain(table, "felix-INPUT")

    table = expected_state.tables_v4["nat"]
    chain = table.chains["PREROUTING"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-PREROUTING"))

    chain = stub_fiptables.get_chain(table, "felix-PREROUTING")
    rule = stub_fiptables.Rule(IPV4)
    rule.protocol = "tcp"
    rule.create_tcp_match("80")
    rule.create_target("DNAT", {'to_destination': '127.0.0.1:9697'})
    chain.rules.append(rule)

    table = expected_state.tables_v6["filter"]
    chain = table.chains["FORWARD"]
    chain.rules.append(stub_fiptables.Rule(IPV6, "felix-FORWARD"))
    chain = table.chains["INPUT"]
    chain.rules.append(stub_fiptables.Rule(IPV6, "felix-INPUT"))
    stub_fiptables.get_chain(table, "felix-FORWARD")
    stub_fiptables.get_chain(table, "felix-INPUT")

