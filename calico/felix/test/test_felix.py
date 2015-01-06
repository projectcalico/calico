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
import logging
import mock
import sys
import time
import unittest
import uuid

import calico.felix.futils as futils

# Import our stub utils module which replaces time etc.
import calico.felix.test.stub_utils as stub_utils

# Replace zmq with our stub zmq.
import calico.felix.test.stub_zmq as stub_zmq
from calico.felix.test.stub_zmq import (TYPE_EP_REQ, TYPE_EP_REP,
                                        TYPE_ACL_REQ, TYPE_ACL_SUB)
sys.modules['zmq'] = stub_zmq

# Hide iptc, since we do not have it.
sys.modules['iptc'] = __import__('calico.felix.test.stub_empty')

# Replace calico.felix.fiptables with calico.felix.test.stub_fiptables
import calico.felix.test.stub_fiptables
sys.modules['calico.felix.fiptables'] = __import__('calico.felix.test.stub_fiptables')
calico.felix.fiptables = calico.felix.test.stub_fiptables
stub_fiptables = calico.felix.test.stub_fiptables

#*****************************************************************************#
#* Load calico.felix.devices and calico.felix.test.stub_devices, and the     *#
#* same for ipsets; we do not blindly override as we need to avoid getting   *#
#* into a state where tests of these modules cannot be made to work.         *#
#*****************************************************************************#
import calico.felix.devices
import calico.felix.test.stub_devices as stub_devices
import calico.felix.ipsets
import calico.felix.test.stub_ipsets as stub_ipsets

# Now import felix, and away we go.
import calico.felix.felix as felix
import calico.felix.endpoint as endpoint
import calico.felix.frules as frules
import calico.common as common
from calico.felix.futils import IPV4, IPV6
from calico.felix.endpoint import Endpoint

# IPtables state.
expected_iptables = stub_fiptables.TableState()
expected_ipsets = stub_ipsets.IpsetState()

# Default config path.
config_path = "calico/felix/test/data/felix_debug.cfg"

# Logger
log = logging.getLogger(__name__)

class TestBasic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Completely replace the devices and ipsets modules.
        cls.real_devices = calico.felix.devices
        endpoint.devices = stub_devices
        cls.real_ipsets = calico.felix.ipsets
        frules.ipsets = stub_ipsets

    @classmethod
    def tearDownClass(cls):
        # Reinstate the modules we overwrote
        endpoint.devices = cls.real_devices
        frules.ipsets = cls.real_ipsets

    def create_patch(self, name):
        return thing

    def setUp(self):
        # Mock out time
        patcher = mock.patch('calico.felix.futils.time_ms')
        patcher.start().side_effect = stub_utils.get_time
        self.addCleanup(patcher.stop)
        
        stub_utils.set_time(0)
        stub_fiptables.reset_current_state()
        stub_devices.reset()
        stub_ipsets.reset()

        expected_iptables.reset()
        expected_ipsets.reset()

    def tearDown(self):
        pass

    def test_startup(self):
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        set_expected_global_rules()
        stub_fiptables.check_state(expected_iptables)
        stub_ipsets.check_state(expected_ipsets)

    def test_no_work(self):
        """
        Test starting up, and sending no work at all.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)
        context.add_poll_result(0)
        agent.run()

        set_expected_global_rules()
        stub_fiptables.check_state(expected_iptables)
        stub_ipsets.check_state(expected_ipsets)

    def test_main_flow(self):
        """
        Test starting up and going through some of the basic flow.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)
        context.add_poll_result(0)
        agent.run()

        # Now we want to reply to the RESYNC request.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data_present())
        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': 1,
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result = context.add_poll_result(50)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        # Felix expects one endpoint created message - give it what it wants
        endpoint_id = str(uuid.uuid4())
        log.debug("Build first endpoint created : %s" % endpoint_id)
        mac = stub_utils.get_mac()
        suffix = endpoint_id[:11]
        tap = "tap" + suffix
        addr = '1.2.3.4'
        endpoint_created_req = { 'type': "ENDPOINTCREATED",
                                 'endpoint_id': endpoint_id,
                                 'resync_id': resync_id,
                                 'issued': futils.time_ms(),
                                 'mac': mac,
                                 'state': Endpoint.STATE_ENABLED,
                                 'addrs': [ {'gateway': "1.2.3.1", 'addr': addr} ] }

        poll_result = context.add_poll_result(100)
        poll_result.add(TYPE_EP_REP, endpoint_created_req)
        agent.run()

        log.debug("Create tap interface %s" % tap)
        tap_obj = stub_devices.TapInterface(tap)
        stub_devices.add_tap(tap_obj)
        poll_result = context.add_poll_result(150)
        agent.run()

        #*********************************************************************#
        #* As soon as that endpoint has been made to exist, we should see an *#
        #* ACL request coming through, and a response to the endpoint        *#
        #* created.  We send a reply to that now.                            *#
        #*********************************************************************#
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        acl_req = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertFalse(context.sent_data_present())
        self.assertEqual(acl_req['endpoint_id'], endpoint_id)

        acl_rsp = { 'type': "GETACLSTATE",
                    'rc': "SUCCESS",
                    'message': "" }
        poll_result = context.add_poll_result(200)
        poll_result.add(TYPE_ACL_REQ, acl_rsp)

        # Check the rules are what we expect.
        set_expected_global_rules()
        add_endpoint_rules(suffix, tap, addr, None, mac)
        stub_fiptables.check_state(expected_iptables)
        add_endpoint_ipsets(suffix)
        stub_ipsets.check_state(expected_ipsets)

        # OK - now try giving it some ACLs, and see if they get applied correctly.
        acls = get_blank_acls()
        acls['v4']['outbound'].append({ 'cidr': "0.0.0.0/0", 'protocol': "icmp" })
        acls['v4']['outbound'].append({ 'cidr': "1.2.3.0/24", 'protocol': "tcp" })
        acls['v4']['outbound'].append({ 'cidr': "0.0.0.0/0", 'protocol': "tcp", 'port': "80" })
        acls['v4']['inbound'].append({ 'cidr': "1.2.2.0/24", 'protocol': "icmp" })
        acls['v4']['inbound'].append({ 'cidr': "0.0.0.0/0", 'protocol': "tcp", 'port': "8080" })
        acls['v4']['inbound'].append({ 'cidr': "2.4.6.8/32", 'protocol': "udp", 'port': "8080" })
        acls['v4']['inbound'].append({ 'cidr': "1.2.3.3/32" })
                                        
        acl_req = { 'type': "ACLUPDATE",
                    'acls': acls }

        poll_result.add(TYPE_ACL_SUB, acl_req, endpoint_id)
        agent.run()

        stub_fiptables.check_state(expected_iptables)
        expected_ipsets.add("felix-from-icmp-" + suffix, "0.0.0.0/1")
        expected_ipsets.add("felix-from-icmp-" + suffix, "128.0.0.0/1")
        expected_ipsets.add("felix-from-port-" + suffix, "1.2.3.0/24,tcp:0")
        expected_ipsets.add("felix-from-port-" + suffix, "0.0.0.0/1,tcp:80")
        expected_ipsets.add("felix-from-port-" + suffix, "128.0.0.0/1,tcp:80")

        expected_ipsets.add("felix-to-icmp-" + suffix, "1.2.2.0/24")
        expected_ipsets.add("felix-to-port-" + suffix, "0.0.0.0/1,tcp:8080")
        expected_ipsets.add("felix-to-port-" + suffix, "128.0.0.0/1,tcp:8080")
        expected_ipsets.add("felix-to-port-" + suffix, "2.4.6.8/32,udp:8080")
        expected_ipsets.add("felix-to-addr-" + suffix, "1.2.3.3/32")

        stub_ipsets.check_state(expected_ipsets)

        # Add another endpoint, and check the state.
        endpoint_id2 = str(uuid.uuid4())
        log.debug("Build second endpoint created : %s" % endpoint_id2)
        mac2 = stub_utils.get_mac()
        suffix2 = endpoint_id2[:11]
        tap2 = "tap" + suffix2
        addr2 = '1.2.3.5'
        endpoint_created_req = { 'type': "ENDPOINTCREATED",
                                 'endpoint_id': endpoint_id2,
                                 'issued': futils.time_ms(),
                                 'mac': mac2,
                                 'state': Endpoint.STATE_ENABLED,
                                 'addrs': [ {'gateway': "1.2.3.1", 'addr': addr2} ] }

        poll_result = context.add_poll_result(250)
        poll_result.add(TYPE_EP_REP, endpoint_created_req)
        tap_obj2 = stub_devices.TapInterface(tap2)
        stub_devices.add_tap(tap_obj2)
        agent.run()

        # Check that we got what we expected - i.e. a success response, a GETACLSTATE,
        # and the rules in the right state.
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        acl_req = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(acl_req['endpoint_id'], endpoint_id2)
        self.assertFalse(context.sent_data_present())

        add_endpoint_rules(suffix2, tap2, addr2, None, mac2)
        stub_fiptables.check_state(expected_iptables)
        add_endpoint_ipsets(suffix2)
        stub_ipsets.check_state(expected_ipsets)

        # OK, finally wind down with an ENDPOINTDESTROYED message for that second endpoint.
        endpoint_destroyed_req = { 'type': "ENDPOINTDESTROYED",
                                   'endpoint_id': endpoint_id2,
                                   'issued': futils.time_ms() }

        poll_result = context.add_poll_result(300)
        poll_result.add(TYPE_EP_REP, endpoint_destroyed_req)
        stub_devices.del_tap(tap2)
        agent.run()

        # Rebuild and recheck the state.
        set_expected_global_rules()
        add_endpoint_rules(suffix, tap, addr, None, mac)
        stub_fiptables.check_state(expected_iptables)

    def test_rule_reordering(self):
        # TODO: Want to check that with extra rules, the extras get tidied up.
        pass

    def test_ipv6_reordering(self):
        # TODO: Want to test IP v6 addresses and rules too.
        pass


def get_blank_acls():
    """
    Return a blank set of ACLs, with nothing permitted.
    """
    acls = {}
    acls['v4'] = {}
    acls['v6'] = {}

    acls['v4']['inbound_default'] = "deny"
    acls['v4']['outbound_default'] = "deny"
    acls['v4']['inbound'] = []
    acls['v4']['outbound'] = []
    acls['v6']['inbound_default'] = "deny"
    acls['v6']['outbound_default'] = "deny"
    acls['v6']['inbound'] = []
    acls['v6']['outbound'] = []
    return acls

def set_expected_global_rules():
    """
    Sets up the minimal global rules we expect to have.
    """
    expected_iptables.reset()

    table = expected_iptables.tables_v4["filter"]
    chain = table._chains_dict["FORWARD"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-FORWARD"))
    chain = table._chains_dict["INPUT"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-INPUT"))
    stub_fiptables.get_chain(table, "felix-FORWARD")
    stub_fiptables.get_chain(table, "felix-INPUT")

    table = expected_iptables.tables_v4["nat"]
    chain = table._chains_dict["PREROUTING"]
    chain.rules.append(stub_fiptables.Rule(IPV4, "felix-PREROUTING"))

    chain = stub_fiptables.get_chain(table, "felix-PREROUTING")
    rule = stub_fiptables.Rule(IPV4)
    rule.protocol = "tcp"
    rule.create_tcp_match("80")
    rule.create_target("DNAT", {'to_destination': '127.0.0.1:9697'})
    chain.rules.append(rule)

    table = expected_iptables.tables_v6["filter"]
    chain = table._chains_dict["FORWARD"]
    chain.rules.append(stub_fiptables.Rule(IPV6, "felix-FORWARD"))
    chain = table._chains_dict["INPUT"]
    chain.rules.append(stub_fiptables.Rule(IPV6, "felix-INPUT"))
    stub_fiptables.get_chain(table, "felix-FORWARD")
    stub_fiptables.get_chain(table, "felix-INPUT")

def add_endpoint_rules(suffix, tap, ipv4, ipv6, mac):
    """
    This adds the rules for an endpoint, appending to the end. This generates
    a clean state to allow us to test that the state is correct, even after
    it starts with extra rules etc.
    """
    table = expected_iptables.tables_v4["filter"]
    chain = table._chains_dict["felix-FORWARD"]
    rule = stub_fiptables.Rule(IPV4, "felix-from-%s" % suffix)
    rule.in_interface = tap
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "felix-to-%s" % suffix)
    rule.out_interface = tap
    chain.rules.append(rule)

    chain = table._chains_dict["felix-INPUT"]
    rule = stub_fiptables.Rule(IPV4, "felix-from-%s" % suffix)
    rule.in_interface = tap
    chain.rules.append(rule)

    chain = stub_fiptables.get_chain(table, "felix-from-%s" % suffix)
    rule = stub_fiptables.Rule(IPV4, "DROP")
    rule.create_conntrack_match(["INVALID"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.protocol = "udp"
    rule.create_udp_match("68", "67")
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "DROP")
    rule.protocol = "udp"
    rule.create_udp_match("67", "68")
    chain.rules.append(rule)

    if ipv4 is not None:
        rule = stub_fiptables.Rule(IPV4)
        rule.create_target("MARK", {"set_mark": "1"})
        rule.src = ipv4
        rule.create_mac_match(mac)
        chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "DROP")
    rule.create_mark_match("!1")
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_set_match(["felix-from-port-%s" % suffix, "dst,dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_set_match(["felix-from-addr-%s" % suffix, "dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.protocol = "icmp"
    rule.create_set_match(["felix-from-icmp-%s" % suffix, "dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "DROP")
    chain.rules.append(rule)

    chain = stub_fiptables.get_chain(table, "felix-to-%s" % suffix)
    rule = stub_fiptables.Rule(IPV4, "DROP")
    rule.create_conntrack_match(["INVALID"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_set_match(["felix-to-port-%s" % suffix, "src,dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.create_set_match(["felix-to-addr-%s" % suffix, "src"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "RETURN")
    rule.protocol = "icmp"
    rule.create_set_match(["felix-to-icmp-%s" % suffix, "src"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV4, "DROP")
    chain.rules.append(rule)

    table = expected_iptables.tables_v6["filter"]
    chain = table._chains_dict["felix-FORWARD"]
    rule = stub_fiptables.Rule(IPV6, "felix-from-%s" % suffix)
    rule.in_interface = tap
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "felix-to-%s" % suffix)
    rule.out_interface = tap
    chain.rules.append(rule)

    chain = table._chains_dict["felix-INPUT"]
    rule = stub_fiptables.Rule(IPV6, "felix-from-%s" % suffix)
    rule.in_interface = tap
    chain.rules.append(rule)

    chain = stub_fiptables.get_chain(table, "felix-from-%s" % suffix)
    rule = stub_fiptables.Rule(type, "RETURN")
    rule.protocol = "icmpv6"
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "DROP")
    rule.create_conntrack_match(["INVALID"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.protocol = "udp"
    rule.create_udp_match("546", "547")
    chain.rules.append(rule)

    if ipv6 is not None:
        rule = stub_fiptables.Rule(IPV6)
        rule.create_target("MARK", {"set_mark": "1"})
        rule.src = ipv6
        rule.create_mac_match(mac)
        chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "DROP")
    rule.create_mark_match("!1")
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_set_match(["felix-6-from-port-%s" % suffix, "dst,dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_set_match(["felix-6-from-addr-%s" % suffix, "dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.protocol = "icmpv6"
    rule.create_set_match(["felix-6-from-icmp-%s" % suffix, "dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "DROP")
    chain.rules.append(rule)

    chain = stub_fiptables.get_chain(table, "felix-to-%s" % suffix)
    for icmp in ["130", "131", "132", "134", "135", "136"]:
        rule = stub_fiptables.Rule(futils.IPV6, "RETURN")
        rule.protocol = "icmpv6"
        rule.create_icmp6_match([icmp])
        chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "DROP")
    rule.create_conntrack_match(["INVALID"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_set_match(["felix-6-to-port-%s" % suffix, "src,dst"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.create_set_match(["felix-6-to-addr-%s" % suffix, "src"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "RETURN")
    rule.protocol = "icmpv6"
    rule.create_set_match(["felix-6-to-icmp-%s" % suffix, "src"])
    chain.rules.append(rule)

    rule = stub_fiptables.Rule(IPV6, "DROP")
    chain.rules.append(rule)


def add_endpoint_ipsets(suffix):
    """
    Sets up the ipsets for a given endpoint. Actual entries in these endpoints
    must then be added manually.
    """
    # Create ipsets if they do not already exist.
    expected_ipsets.create("felix-to-port-" + suffix, "hash:net,port", "inet")
    expected_ipsets.create("felix-to-addr-" + suffix, "hash:net", "inet")
    expected_ipsets.create("felix-to-icmp-" + suffix, "hash:net", "inet")
    expected_ipsets.create("felix-from-port-" + suffix, "hash:net,port", "inet")
    expected_ipsets.create("felix-from-addr-" + suffix, "hash:net", "inet")
    expected_ipsets.create("felix-from-icmp-" + suffix, "hash:net", "inet")

    expected_ipsets.create("felix-6-to-port-" + suffix, "hash:net,port", "inet6")
    expected_ipsets.create("felix-6-to-addr-" + suffix, "hash:net", "inet6")
    expected_ipsets.create("felix-6-to-icmp-" + suffix, "hash:net", "inet6")
    expected_ipsets.create("felix-6-from-port-" + suffix, "hash:net,port", "inet6")
    expected_ipsets.create("felix-6-from-addr-" + suffix, "hash:net", "inet6")
    expected_ipsets.create("felix-6-from-icmp-" + suffix, "hash:net", "inet6")
