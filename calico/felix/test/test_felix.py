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
import pkg_resources
import socket
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
import calico.felix.fsocket as fsocket

# Stub out a few bits of fiptables.
import calico.felix.test.stub_fiptables as stub_fiptables

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
import calico.felix.fiptables as fiptables
import calico.felix.endpoint as endpoint
import calico.felix.frules as frules
import calico.common as common
from calico.felix.futils import IPV4, IPV6
from calico.felix.endpoint import Endpoint
from calico.felix.fsocket import Socket

# IPtables state.
expected_iptables = stub_fiptables.TableState()
expected_ipsets = stub_ipsets.IpsetState()

# Dummy out package resolution, so it works from a git checkout
def dummy_package(name):
    return "calico version"
pkg_resources.get_distribution = dummy_package

# Default config path.
config_path = "calico/felix/test/data/felix_debug.cfg"

# Logger
log = logging.getLogger(__name__)

class TestFelixSuperclass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Completely replace the devices and ipsets modules.
        cls.real_devices = calico.felix.devices
        endpoint.devices = stub_devices
        cls.real_ipsets = calico.felix.ipsets
        frules.ipsets = stub_ipsets
        cls.real_TableState = fiptables.TableState
        calico.felix.fiptables.TableState = stub_fiptables.TableState

    @classmethod
    def tearDownClass(cls):
        # Reinstate the modules we overwrote
        endpoint.devices = cls.real_devices
        frules.ipsets = cls.real_ipsets
        fiptables.TableState = cls.real_TableState

    def setUp(self):
        # Mock out time
        patcher = mock.patch('calico.felix.futils.time_ms')
        patcher.start().side_effect = stub_utils.get_time
        self.addCleanup(patcher.stop)

        stub_utils.set_time(0)
        stub_devices.reset()
        stub_ipsets.reset()

        # Set the expected IP tables state to be clean.
        expected_iptables.set_empty()
        expected_ipsets.reset()

    def tearDown(self):
        pass


class TestBasic(TestFelixSuperclass):
    def test_startup(self):
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        expected_iptables.set_expected_global_rules()
        agent.iptables_state.check_state(expected_iptables)
        stub_ipsets.check_state(expected_ipsets)

        self.assertEqual(agent.hostname, "test_hostname")

    def test_no_work(self):
        """
        Test starting up, and sending no work at all.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)
        context.add_poll_result(0)
        agent.run()

        expected_iptables.set_expected_global_rules()
        agent.iptables_state.check_state(expected_iptables)
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
        addr = "1.2.3.4"
        endpoint = CreatedEndpoint([addr])
        log.debug("Build first endpoint created : %s", endpoint.id)
        poll_result = context.add_poll_result(100)
        poll_result.add(TYPE_EP_REP, endpoint.create_req)
        agent.run()

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
        self.assertEqual(acl_req['endpoint_id'], endpoint.id)

        acl_rsp = { 'type': "GETACLSTATE",
                    'rc': "SUCCESS",
                    'message': "" }
        poll_result = context.add_poll_result(200)
        poll_result.add(TYPE_ACL_REQ, acl_rsp)

        # Check the rules are what we expect.
        expected_iptables.set_expected_global_rules()
        expected_iptables.add_endpoint_rules(endpoint.suffix, endpoint.interface,
                                             addr, None, endpoint.mac)
        agent.iptables_state.check_state(expected_iptables)
        add_endpoint_ipsets(endpoint.suffix)
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
        acls['v4']['inbound'].append({ 'cidr': "3.6.9.12/32",
                                       'protocol': "tcp",
                                       'port': ['10', '50'] })

        acls['v4']['inbound'].append({ 'cidr': "5.4.3.2/32",
                                       'protocol': "icmp",
                                       'icmp_type': "3",
                                       'icmp_code': "2" })

        acls['v4']['inbound'].append({ 'cidr': "5.4.3.2/32",
                                       'protocol': "icmp",
                                       'icmp_type': "9" })

        acls['v4']['inbound'].append({ 'cidr': "5.4.3.2/32",
                                       'protocol': "icmp",
                                       'icmp_type': "blah" })

        # We include a couple of invalid rules that Felix will just ignore (and log).
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "tcp",
                                       'port': ['blah', 'blah'] })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "tcp",
                                       'port': ['1', '2', '3'] })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "tcp",
                                       'port': 'flibble' })
        acls['v4']['inbound'].append({ 'protocol': "tcp" })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'port': "123" })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "icmp",
                                       'icmp_code': "blah" })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "icmp",
                                       'port': "1" })
        acls['v4']['inbound'].append({ 'cidr': "4.3.2.1/32",
                                       'protocol': "rsvp",
                                       'port': "1" })

        acl_req = { 'type': "ACLUPDATE",
                    'acls': acls }

        poll_result.add(TYPE_ACL_SUB, acl_req, endpoint.id)
        agent.run()

        agent.iptables_state.check_state(expected_iptables)

        expected_ipsets.add("felix-from-icmp-" + endpoint.suffix, "0.0.0.0/1")
        expected_ipsets.add("felix-from-icmp-" + endpoint.suffix, "128.0.0.0/1")
        expected_ipsets.add("felix-from-port-" + endpoint.suffix, "1.2.3.0/24,tcp:0")
        expected_ipsets.add("felix-from-port-" + endpoint.suffix, "0.0.0.0/1,tcp:80")
        expected_ipsets.add("felix-from-port-" + endpoint.suffix, "128.0.0.0/1,tcp:80")

        expected_ipsets.add("felix-to-icmp-" + endpoint.suffix, "1.2.2.0/24")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "0.0.0.0/1,tcp:8080")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "128.0.0.0/1,tcp:8080")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "2.4.6.8/32,udp:8080")
        expected_ipsets.add("felix-to-addr-" + endpoint.suffix, "1.2.3.3/32")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "3.6.9.12/32,tcp:10-50")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "5.4.3.2/32,icmp:3/2")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "5.4.3.2/32,icmp:9/0")
        expected_ipsets.add("felix-to-port-" + endpoint.suffix, "5.4.3.2/32,icmp:blah")

        stub_ipsets.check_state(expected_ipsets)

        # Add another endpoint, and check the state.
        addr2 = "1.2.3.5"
        endpoint2 = CreatedEndpoint([addr2])
        log.debug("Build second endpoint created : %s", endpoint2.id)
        poll_result = context.add_poll_result(250)
        poll_result.add(TYPE_EP_REP, endpoint2.create_req)
        agent.run()

        # Check that we got what we expected - i.e. a success response, a GETACLSTATE,
        # and the rules in the right state.
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        acl_req = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(acl_req['endpoint_id'], endpoint2.id)
        self.assertFalse(context.sent_data_present())

        expected_iptables.add_endpoint_rules(endpoint2.suffix, endpoint2.interface,
                                             addr2, None, endpoint2.mac)
        agent.iptables_state.check_state(expected_iptables)
        add_endpoint_ipsets(endpoint2.suffix)
        agent.iptables_state.check_state(expected_iptables)

        # OK, finally wind down with an ENDPOINTDESTROYED message for that second endpoint.
        poll_result = context.add_poll_result(300)
        poll_result.add(TYPE_EP_REP, endpoint2.destroy_req)
        stub_devices.del_interface(endpoint2.interface)
        agent.run()

        # Rebuild and recheck the state. Only the first endpoint still exists.
        expected_iptables.set_expected_global_rules()
        expected_iptables.add_endpoint_rules(endpoint.suffix, endpoint.interface,
                                             addr, None, endpoint.mac)
        agent.iptables_state.check_state(expected_iptables)

    def test_destroy_absent_endpoint(self):
        """
        Test receiving ENDPOINTDESTROYED for a non-existent endpoint.
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
                       'endpoint_count': 0,
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result = context.add_poll_result(50)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        # Send ENDPOINTDESTROYED for an endpoint that does not exist.
        addr = "1.2.3.4"
        endpoint = CreatedEndpoint([addr])
        log.debug("Build endpoint destroyed : %s", endpoint.id)
        poll_result = context.add_poll_result(100)
        poll_result.add(TYPE_EP_REP, endpoint.destroy_req)
        agent.run()

        #*********************************************************************#
        #* Expect an ENDPOINTDESTROYED response saying NOTEXIST.             *#
        #*********************************************************************#
        endpoint_destroyed_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_destroyed_rsp['rc'], "NOTEXIST")

    def test_rule_reordering(self):
        # TODO: Want to check that with extra rules, the extras get tidied up.
        pass

    def test_ipv6_reordering(self):
        # TODO: Want to test IP v6 addresses and rules too.
        pass


class TestTimings(TestFelixSuperclass):
    def test_resync(self):
        """
        Test the resync flows.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        #*********************************************************************#
        #* Set the resync timeout to 5 seconds, and the KEEPALIVE timeout to *#
        #* much more.                                                        *#
        #*********************************************************************#
        agent.config.RESYNC_INT_SEC = 5
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 50000

        # Get started.
        context.add_poll_result(0)
        agent.run()

        # Now we should have got a resync request.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data_present())
        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "0",
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result = context.add_poll_result(1000)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()
        # nothing yet
        self.assertFalse(context.sent_data_present())

        poll_result = context.add_poll_result(5999)
        agent.run()
        # nothing yet - 4999 ms since last request
        self.assertFalse(context.sent_data_present())

        poll_result = context.add_poll_result(6001)
        agent.run()

        # We should have got another resync request.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data_present())
        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "2",
                       'rc': "SUCCESS",
                       'message': "hello" }

        # No more resyncs until enough data has arrived.
        poll_result = context.add_poll_result(15000)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()
        self.assertFalse(context.sent_data_present())

        # Send an endpoint created message to Felix.
        addr = '1.2.3.4'
        endpoint = CreatedEndpoint([addr], resync_id)
        log.debug("Build first endpoint created : %s", endpoint.id)
        poll_result = context.add_poll_result(15001)
        poll_result.add(TYPE_EP_REP, endpoint.create_req)
        agent.run()

        # We stop using sent_data_present, since there are ACL requests around.
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")
        self.assertFalse(context.sent_data[TYPE_EP_REQ])

        # Send a second endpoint created message to Felix - triggers another resync.
        addr = '1.2.3.5'
        endpoint2 = CreatedEndpoint([addr], resync_id)
        log.debug("Build second endpoint created : %s" % endpoint2.id)

        poll_result = context.add_poll_result(15002)
        poll_result.add(TYPE_EP_REP, endpoint2.create_req)
        agent.run()

        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")
        self.assertFalse(context.sent_data[TYPE_EP_REQ])

        # No more resyncs until enough 5000 ms after last rsp.
        poll_result = context.add_poll_result(20000)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()
        self.assertFalse(context.sent_data[TYPE_EP_REQ])

        # We should have got another resync request.
        poll_result = context.add_poll_result(20003)
        poll_result.add(TYPE_EP_REP, endpoint2.create_req)
        agent.run()
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data[TYPE_EP_REQ])

    def test_keepalives(self):
        """
        Test that keepalives are sent.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        agent.config.RESYNC_INT_SEC = 500
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 5000

        # Get started.
        context.add_poll_result(0)
        agent.run()

        # Now we should have got a resync request.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data_present())
        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "0",
                       'rc': "SUCCESS",
                       'message': "hello" }

        # We should send keepalives on the 5 second boundary.
        poll_result = context.add_poll_result(4999)
        agent.run()
        self.assertFalse(context.sent_data_present())

        poll_result = context.add_poll_result(5001)
        agent.run()
        keepalive = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertTrue(keepalive['type'] == "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

        # Send the resync response now
        poll_result = context.add_poll_result(6000)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()
        self.assertFalse(context.sent_data_present())

        # At time 9000, send the ACL response.
        poll_result = context.add_poll_result(9000)
        poll_result.add(TYPE_ACL_REQ,
                        {'type': "HEARTBEAT", 'rc': "SUCCESS"})
        agent.run()
        self.assertFalse(context.sent_data_present())

        # Now we should get another keepalive sent at 14 seconds on ACL_REQ,
        # and 11 on EP_REQ
        poll_result = context.add_poll_result(11001)
        agent.run()
        keepalive = context.sent_data[TYPE_EP_REQ].pop()
        self.assertTrue(keepalive['type'] == "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

        poll_result = context.add_poll_result(14001)
        agent.run()
        keepalive = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertTrue(keepalive['type'] == "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

    def test_timeouts(self):
        """
        Test that connections time out correctly.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        agent.config.RESYNC_INT_SEC = 500
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 5000

        # Get started.
        context.add_poll_result(0)
        agent.run()

        sock_zmq = {}
        for sock in agent.sockets.values():
            sock_zmq[sock] = sock._zmq

        # Now we should have got a resync request.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        log.debug("Resync request : %s" % resync_req)
        self.assertFalse(context.sent_data_present())
        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "0",
                       'rc': "SUCCESS",
                       'message': "hello" }

        # Send keepalives on the connections that expect them
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        poll_result.add(TYPE_EP_REP, {'type': "HEARTBEAT"})
        poll_result.add(TYPE_ACL_SUB, {'type': "HEARTBEAT"}, 'aclheartbeat')
        agent.run()

        # Give EP REQ a chance to send a keepalive.
        context.add_poll_result(10000)
        agent.run()

        # OK, so now we have some live connections. We let the EP REQ fail
        # first.
        context.add_poll_result(10000)
        agent.run()
        msg = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        msg = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        msg = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

        # And another 20 seconds
        poll_result = context.add_poll_result(40000)
        poll_result.add(TYPE_EP_REP, {'type': "HEARTBEAT"})
        poll_result.add(TYPE_ACL_SUB, {'type': "HEARTBEAT"}, 'aclheartbeat')
        poll_result.add(TYPE_ACL_REQ,
                        {'type': "HEARTBEAT", 'rc': "SUCCESS"})
        agent.run()
        for sock in agent.sockets.values():
            # Assert no connections have been restarted.
            self.assertIs(sock_zmq[sock], sock._zmq)

        # And another - which should lead to EP REQ going pop, and keepalives.
        context.add_poll_result(60000)
        agent.run()
        for sock in agent.sockets.values():
            if sock.type == TYPE_EP_REQ:
                self.assertIsNot(sock_zmq[sock], sock._zmq)
                sock_zmq[sock] = sock._zmq
            else:
                self.assertIs(sock_zmq[sock], sock._zmq)

        msg = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        msg = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

        # That connection that came up should be sending keepalives
        context.add_poll_result(70000)
        agent.run()
        msg = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")
        self.assertFalse(context.sent_data_present())

        # OK, so now time out the EP REP socket. This triggers a resync.
        poll_result = context.add_poll_result(80000)
        poll_result.add(TYPE_EP_REQ,
                        {'type': "HEARTBEAT", 'rc': "SUCCESS"})
        poll_result.add(TYPE_ACL_SUB, {'type': "HEARTBEAT"}, 'aclheartbeat')
        poll_result.add(TYPE_ACL_REQ,
                        {'type': "HEARTBEAT", 'rc': "SUCCESS"})
        agent.run()

        # This is the point where the EP REP socket is going to die.
        log.debug("EP REP should now trigger resync")
        poll_result = context.add_poll_result(120000)
        agent.run()
        msg = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(msg['type'], "RESYNCSTATE")
        resync_id = msg['resync_id']
        msg = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(msg['type'], "HEARTBEAT")

        for sock in agent.sockets.values():
            # Assert no connections have been restarted.
            self.assertIs(sock_zmq[sock], sock._zmq)

        # OK, so send some messages in response.
        poll_request = context.add_poll_result(120000)
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "5",
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        addrs = [ "2001::%s" + str(i) for i in range(1,6) ]
        endpoints = []
        for addr in addrs:
            endpoint = CreatedEndpoint([addr], resync_id)
            endpoints.append(endpoint)

            poll_result = context.add_poll_result(120000)
            poll_result.add(TYPE_EP_REP, endpoint.create_req)
            agent.run()

            endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        # OK, so get the first two ACL state messages, blocked behind the heartbeat.
        poll_result = context.add_poll_result(120000)
        poll_result.add(TYPE_ACL_REQ,
                        {'type': "HEARTBEAT", 'rc': "SUCCESS"})
        agent.run()

        acl_req = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(acl_req['type'], "GETACLSTATE")
        self.assertEqual(acl_req['endpoint_id'], endpoints[0].id)

        poll_result = context.add_poll_result(120000)
        poll_result.add(TYPE_ACL_REQ,
                        {'type': "GETACLSTATE", 'rc': "SUCCESS", 'message': "" })
        agent.run()

        acl_req = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(acl_req['type'], "GETACLSTATE")
        self.assertEqual(acl_req['endpoint_id'], endpoints[1].id)

        #*********************************************************************#
        #* OK, so let's pretend that the ACL SUB connection has gone away.   *#
        #* We've done keepalives to the Nth degree, so are about to start    *#
        #* cheating a bit, and will tweak _last_activity in the socket to    *#
        #* force timeouts to make the test (much) simpler.                   *#
        #*********************************************************************#
        agent.sockets[TYPE_ACL_SUB]._last_activity = 0
        poll_result = context.add_poll_result(120000)
        agent.run()

        for sock in agent.sockets.values():
            if sock.type == TYPE_ACL_SUB:
                self.assertIsNot(sock_zmq[sock], sock._zmq)
                sock_zmq[sock] = sock._zmq
            else:
                self.assertIs(sock_zmq[sock], sock._zmq)

        #*********************************************************************#
        #* The ACL request connection is up, and it should send us 5         *#
        #* messages. Recall that there is already one outstanding            *#
        #* GETACLSTATE, so acknowledge that first.                           *#
        #*********************************************************************#
        for i in range(1,6):
            poll_result = context.add_poll_result(120000)
            poll_result.add(TYPE_ACL_REQ,
                            {'type': "GETACLSTATE", 'rc': "SUCCESS", 'message': ""})

            agent.run()

            acl_req = context.sent_data[TYPE_ACL_REQ].pop()
            self.assertEqual(acl_req['type'], "GETACLSTATE")


        #*********************************************************************#
        #* There should be no more messages - i.e. just the 5.               *#
        #*********************************************************************#
        poll_result = context.add_poll_result(120000)
        agent.run()
        self.assertFalse(context.sent_data_present())

        #*********************************************************************#
        #* Make the ACL REQ connection go away, with similar results.        *#
        #*********************************************************************#
        agent.sockets[TYPE_ACL_REQ]._last_activity = 0
        poll_result = context.add_poll_result(120000)
        agent.run()

        for sock in agent.sockets.values():
            if sock.type == TYPE_ACL_REQ:
                self.assertIsNot(sock_zmq[sock], sock._zmq)
                sock_zmq[sock] = sock._zmq
            else:
                self.assertIs(sock_zmq[sock], sock._zmq)

        for i in range(1,6):
            acl_req = context.sent_data[TYPE_ACL_REQ].pop()
            self.assertEqual(acl_req['type'], "GETACLSTATE")

            poll_result = context.add_poll_result(120000)
            poll_result.add(TYPE_ACL_REQ,
                            {'type': "GETACLSTATE", 'rc': "SUCCESS", 'message': ""})

            agent.run()

    def test_queues(self):
        """
        Test queuing.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        agent.config.RESYNC_INT_SEC = 500
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 5000

        # Get started.
        context.add_poll_result(0)
        agent.run()

        # Who cares about the resync request - just reply right away.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        self.assertFalse(context.sent_data_present())

        context.add_poll_result(0)
        agent.run()
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "0",
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        # OK, so let's just trigger a bunch of endpoint creations. Each of
        # these does some work that we don't care about. What we do care about
        # is that the queues get managed.
        addrs = [ "192.168.0." + str(i) for i in range(1,11) ]
        endpoints = []
        for addr in addrs:
            endpoint = CreatedEndpoint([addr])
            endpoints.append(endpoint)

            poll_result = context.add_poll_result(1)
            poll_result.add(TYPE_EP_REP, endpoint.create_req)
            agent.run()

            endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        #*********************************************************************#
        #* OK, we just threw 10 ENDPOINTCREATED requests in. There should be *#
        #* 10 ACLUPDATE requests out there for those endpoints, in           *#
        #* order. Grab them, spinning things out long enough that keepalives *#
        #* would be sent and connections torn down if there was no other     *#
        #* activity.                                                         *#
        #*********************************************************************#
        sock_zmq = {}
        for sock in agent.sockets.values():
            sock_zmq[sock] = sock._zmq

        poll_result = context.add_poll_result(6000)
        poll_result.add(TYPE_EP_REP, {'type': "HEARTBEAT"})
        poll_result.add(TYPE_ACL_SUB, {'type': "HEARTBEAT"}, 'aclheartbeat')

        acl_req_sock = agent.sockets[TYPE_ACL_REQ]

        for i in range(1,11):
            log.debug("Check status; iteration %d", i)

            agent.run()

            self.assertEqual(len(acl_req_sock._send_queue), 10 - i)

            poll_result = context.add_poll_result(20000 * i)

            acl_req = context.sent_data[TYPE_ACL_REQ].pop()
            self.assertEqual(acl_req['type'], "GETACLSTATE")
            self.assertEqual(acl_req['endpoint_id'], endpoints[i - 1].id)
            poll_result.add(TYPE_ACL_REQ,
                            {'type': "GETACLSTATE", 'rc': "SUCCESS", 'message': "" })

            # Heartbeats for the other connections.
            keepalive_rsp = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(keepalive_rsp['type'], "HEARTBEAT")
            poll_result.add(TYPE_EP_REP, {'type': "HEARTBEAT"})

            keepalive = context.sent_data[TYPE_EP_REQ].pop()
            self.assertEqual(keepalive['type'], "HEARTBEAT")
            poll_result.add(TYPE_EP_REQ, {'type': "HEARTBEAT", 'rc': "SUCCESS"})

            # ACL SUB does not need responses.
            poll_result.add(TYPE_ACL_SUB, {'type': "HEARTBEAT"}, 'aclheartbeat')

            self.assertFalse(context.sent_data_present())

            # We now wait long enough that a keepalive will appear.
            agent.run()
            poll_result = context.add_poll_result(20000 * i + 10000)

        # Check the ACL_REQ keepalives have started.
        poll_result = context.add_poll_result(20000 * i + 10000)
        agent.run()

        keepalive = context.sent_data[TYPE_ACL_REQ].pop()
        self.assertEqual(keepalive['type'], "HEARTBEAT")

        for sock in agent.sockets.values():
            # Assert no connections have been restarted.
            self.assertIs(sock_zmq[sock], sock._zmq)

    def test_resync_timeouts(self):
        """
        Test timeouts during resyncs
        """
        #TODO: Should include rules and ipsets too.
        common.default_logging()
        context = stub_zmq.Context()
        stub_utils.set_time(100000)
        agent = felix.FelixAgent(config_path, context)

        agent.config.RESYNC_INT_SEC = 500
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 5000

        sock_zmq = {}
        for sock in agent.sockets.values():
            sock_zmq[sock] = sock._zmq

        # Get started.
        context.add_poll_result(100000)
        agent.run()

        # Check resync is there, throw it away.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(resync_req['type'], "RESYNCSTATE")
        resync_id = resync_req['resync_id']
        self.assertFalse(context.sent_data_present())

        # Force resync to be replaced by tearing down EP_REQ when outstanding.
        agent.sockets[TYPE_EP_REQ]._last_activity = 0
        context.add_poll_result(100000)
        agent.run()

        for sock in agent.sockets.values():
            log.debug("Check socket %s", sock.type)
            if sock.type == TYPE_EP_REQ:
                self.assertIsNot(sock_zmq[sock], sock._zmq)
                sock_zmq[sock] = sock._zmq
            else:
                self.assertIs(sock_zmq[sock], sock._zmq)

        # As if by magic, another resync has appeared.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(resync_req['type'], "RESYNCSTATE")
        self.assertNotEqual(resync_req['resync_id'], resync_id)
        resync_id = resync_req['resync_id']
        self.assertFalse(context.sent_data_present())

        resync_id = resync_req['resync_id']
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': 0,
                       'rc': "SUCCESS",
                       'message': "hello" }

        poll_result = context.add_poll_result(100000)
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        # Force another resync by timing out the EP_REP connection.
        agent.sockets[TYPE_EP_REP]._last_activity = 0
        context.add_poll_result(100000)
        agent.run()

        for sock in agent.sockets.values():
            self.assertIs(sock_zmq[sock], sock._zmq)

        # As if by magic, another resync has appeared.
        resync_req = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(resync_req['type'], "RESYNCSTATE")
        self.assertNotEqual(resync_req['resync_id'], resync_id)
        resync_id = resync_req['resync_id']
        self.assertFalse(context.sent_data_present())

    def test_resync_tidy_up(self):
        """
        Check that endpoints are removed where required.
        """
        common.default_logging()
        context = stub_zmq.Context()
        stub_utils.set_time(100000)
        agent = felix.FelixAgent(config_path, context)

        agent.config.RESYNC_INT_SEC = 500
        agent.config.CONN_TIMEOUT_MS = 50000
        agent.config.CONN_KEEPALIVE_MS = 5000

        poll_result = context.add_poll_result(0)
        agent.run()

        msg = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(msg['type'], "RESYNCSTATE")
        resync_id = msg['resync_id']

        # OK, so send some messages in response.
        poll_result = context.add_poll_result(0)
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "5",
                       'rc': "SUCCESS",
                       'message': "hello" }
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        addrs = [ "2001::%s" + str(i) for i in range(1,6) ]
        ep_ids = set()
        endpoints = []
        for addr in addrs:
            endpoint = CreatedEndpoint([addr], resync_id)
            endpoints.append(endpoint)
            ep_ids.add(endpoint.id)

            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, endpoint.create_req)
            agent.run()

            endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        # Check that the endpoints are as expected.
        self.assertEqual(ep_ids, set(agent.endpoints.keys()))

        # Now delete an endpoint.
        endpoint = endpoints.pop()
        ep_ids.remove(endpoint.id)
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, endpoint.destroy_req)
        agent.run()
        self.assertEqual(ep_ids, set(agent.endpoints.keys()))

        # Now force another resync, with different data.
        agent.sockets[TYPE_EP_REP]._last_activity = -100000
        poll_result = context.add_poll_result(0)
        agent.run()

        msg = context.sent_data[TYPE_EP_REQ].pop()
        self.assertEqual(msg['type'], "RESYNCSTATE")
        resync_id = msg['resync_id']

        # OK, so now we create two more endpoint.
        new_endpoint = CreatedEndpoint(["1.2.3.4"])
        ep_ids.add(new_endpoint.id)

        rm_endpoint = endpoints.pop()

        poll_result = context.add_poll_result(0)
        resync_rsp = { 'type': "RESYNCSTATE",
                       'endpoint_count': "4",
                       'rc': "SUCCESS",
                       'message': "hello" }
        poll_result.add(TYPE_EP_REQ, resync_rsp)
        agent.run()

        for endpoint in endpoints:
            endpoint.create_req['resync_id'] = resync_id
            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, endpoint.create_req)
            agent.run()
            endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, new_endpoint.create_req)
        agent.run()
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")

        #*********************************************************************#
        #* We have added 4 pre-existing endpoints, and a new endpoint. The   *#
        #* new endpoint does not count (not part of the resync), so does not *#
        #* trigger tidy up of rm_endpoint.                                   *#
        #*********************************************************************#
        self.assertEqual(ep_ids, set(agent.endpoints.keys()))

        #*********************************************************************#
        #* Add one more endpoint in the resync, and tidy up will occur.      *#
        #*********************************************************************#
        ep_ids.remove(rm_endpoint.id)

        log.debug("Add a new endpoint to complete resync")
        new_endpoint2 = CreatedEndpoint(["1.2.3.5"], resync_id)
        ep_ids.add(new_endpoint2.id)
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, new_endpoint2.create_req)
        agent.run()
        endpoint_created_rsp = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(endpoint_created_rsp['rc'], "SUCCESS")
        self.assertEqual(ep_ids, set(agent.endpoints.keys()))


class TestInterfacePrefix(TestFelixSuperclass):
    def test_interface_specification(self):
        """
        Test with a non-standard interface setup.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent("calico/felix/test/data/felix_veth.cfg",
                                 context)
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
        addr = "1.2.3.4"
        endpoint = CreatedEndpoint([addr], prefix="veth")
        log.debug("Build first endpoint created : %s", endpoint.id)
        poll_result = context.add_poll_result(100)
        poll_result.add(TYPE_EP_REP, endpoint.create_req)
        agent.run()

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
        self.assertEqual(acl_req['endpoint_id'], endpoint.id)

        acl_rsp = { 'type': "GETACLSTATE",
                    'rc': "SUCCESS",
                    'message': "" }
        poll_result = context.add_poll_result(200)
        poll_result.add(TYPE_ACL_REQ, acl_rsp)

        # Check the rules are what we expect.
        expected_iptables.set_expected_global_rules("veth")
        expected_iptables.add_endpoint_rules(endpoint.suffix, endpoint.interface,
                                             addr, None, endpoint.mac)
        agent.iptables_state.check_state(expected_iptables)
        add_endpoint_ipsets(endpoint.suffix)
        stub_ipsets.check_state(expected_ipsets)

        #*********************************************************************#
        #* Now give it another endpoint created, with an explicit interface. *#
        #*********************************************************************#
        addr = "1.2.3.5"
        endpoint = CreatedEndpoint([addr], interface="veth_12345")
        log.debug("Build first endpoint created : %s", endpoint.id)
        poll_result = context.add_poll_result(200)
        poll_result.add(TYPE_EP_REP, endpoint.create_req)
        agent.run()

        poll_result = context.add_poll_result(200)
        agent.run()

        self.assertEqual(agent.endpoints[endpoint.id].interface, "veth_12345")


class TestMessages(TestFelixSuperclass):
    def test_invalid_ep_requests(self):
        """
        Test a range of invalid EP created messages.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        # We build a valid endpoint request, then monkey with it.
        addr = "1.2.3.4"
        endpoint = CreatedEndpoint([addr])

        for missing in ["endpoint_id", "mac", "resync_id", "state", "addrs"]:
            log.debug("Testing ENDPOINTCREATED with missing %s", missing)
            request = endpoint.create_req.copy()
            del request[missing]
            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, request)
            agent.run()
            response = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(response['rc'], "INVALID")
            self.assertIn("Missing \"%s\" field" % missing, response['message'])

        log.debug("Testing ENDPOINTCREATED with invalid interface")
        request = endpoint.create_req.copy()
        request['interface_id'] = "bloop"
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        agent.run()
        response = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(response['rc'], "INVALID")
        self.assertIn("Interface \"bloop\" does not start with \"tap\"",
                      response['message'])

        log.debug("Testing ENDPOINTCREATED with invalid state")
        request = endpoint.create_req.copy()
        request['state'] = "bloop"
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        agent.run()
        response = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(response['rc'], "INVALID")
        self.assertIn("Invalid state \"bloop\"", response['message'])

        log.debug("Testing ENDPOINTCREATED with addresses with no IP in address")
        request = endpoint.create_req.copy()
        request['addrs'] = [{'gateway':"1.2.3.4"}]
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        agent.run()
        response = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(response['rc'], "INVALID")
        self.assertIn("Missing \"addr\" field", response['message'])

        for missing in ["endpoint_id"]:
            log.debug("Testing ENDPOINTDESTROYED with missing %s", missing)
            request = endpoint.destroy_req.copy()
            del request[missing]
            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, request)
            agent.run()
            response = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(response['rc'], "INVALID")
            self.assertIn("Missing \"%s\" field" % missing, response['message'])

        for missing in ["endpoint_id", "mac", "state", "addrs"]:
            log.debug("Testing ENDPOINTUPDATED with missing %s", missing)
            request = endpoint.create_req.copy()
            request['type'] = "ENDPOINTUPDATED"
            del request[missing]
            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, request)
            agent.run()
            response = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(response['rc'], "INVALID")
            self.assertIn("Missing \"%s\" field" % missing, response['message'])

        # Invalid message type
        log.debug("Testing invalid message type")
        request = endpoint.create_req.copy()
        request['type'] = "ENDPOINTINVALID"
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        with self.assertRaisesRegexp(felix.InvalidRequest,
                                     "Unrecognised message type"):
            agent.run()

        # TODO: Missing message type currently just produces a KeyError.
        log.debug("Testing missing message type")
        request = endpoint.create_req.copy()
        del request['type']
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        with self.assertRaisesRegexp(KeyError, "type"):
            agent.run()

    def test_invalid_resync_responses(self):
        """
        Test invalid resync responses.
        """
        common.default_logging()

        for missing in [ 'endpoint_count', 'rc', 'message', None ]:
            with mock.patch('calico.felix.felix.FelixAgent.complete_endpoint_resync') \
                 as mock_complete:
                context = stub_zmq.Context()
                agent = felix.FelixAgent(config_path, context)

                resync_req = context.sent_data[TYPE_EP_REQ].pop()
                log.debug("Resync request : %s" % resync_req)
                self.assertFalse(context.sent_data_present())
                resync_id = resync_req['resync_id']
                resync_rsp = { 'type': "RESYNCSTATE",
                               'endpoint_count': 1,
                               'rc': "SUCCESS",
                               'message': "hello" }

                if missing is None:
                    resync_rsp['rc'] = "BLEARGH!"
                else:
                    resync_rsp.pop(missing)
                poll_result = context.add_poll_result(50)
                poll_result.add(TYPE_EP_REQ, resync_rsp)
                agent.run()

                self.assertEqual(mock_complete.call_count, 1)
                mock_complete.assert_has_calls([mock.call(False)])


    def test_invalid_acl_responses(self):
        """
        Test sending invalid responses to GETACLSTATE. We just directly
        inject it since the code does nothing but log it anyway.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)
        sock = agent.sockets[TYPE_ACL_REQ]

        fields = {'message': "Hello"}
        agent.handle_getaclstate(fsocket.Message("GETACLSTATE", fields),
                                 sock)

        fields = {'rc': "SUCCESS"}
        agent.handle_getaclstate(fsocket.Message("GETACLSTATE", fields),
                                 sock)

        fields = {'rc': "WHOOPS", 'message': "Hello" }
        agent.handle_getaclstate(fsocket.Message("GETACLSTATE", fields),
                                 sock)


    def test_odd_ep_requests(self):
        """
        Test some endpoint requests in slightly odd states.
        """
        common.default_logging()
        context = stub_zmq.Context()
        agent = felix.FelixAgent(config_path, context)

        # We build a valid endpoint request, then monkey with it.
        addr = "1.2.3.4"
        endpoint = CreatedEndpoint([addr])

        log.debug("Testing ENDPOINTUPDATED when does not exist")
        request = endpoint.create_req.copy()
        request['type'] = "ENDPOINTUPDATED"
        del request['resync_id']
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        agent.run()
        response = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(response['rc'], "NOTEXIST")
        self.assertIn("does not exist", response['message'])

        # Now create twice - both should succeed.
        log.debug("Issue ENDPOINTCREATED twice")
        for loop in range(0,2):
            request = endpoint.create_req.copy()
            poll_result = context.add_poll_result(0)
            poll_result.add(TYPE_EP_REP, request)
            agent.run()
            response = context.sent_data[TYPE_EP_REP].pop()
            self.assertEqual(response['rc'], "SUCCESS")

        log.debug("Testing ENDPOINTCREATED with empty set of addresses")
        endpoint = CreatedEndpoint([])
        request = endpoint.create_req.copy()
        poll_result = context.add_poll_result(0)
        poll_result.add(TYPE_EP_REP, request)
        agent.run()
        response = context.sent_data[TYPE_EP_REP].pop()
        self.assertEqual(response['rc'], "SUCCESS")


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


class CreatedEndpoint(object):
    """
    Builds an object which contains all the information we might need. Useful
    if we want to just create one for test purposes.

    addresses is a list or set of addresses; we just need to iterate over it.
    """
    def __init__(self, addresses, resync_id="", prefix="tap", interface=None):
        self.id = str(uuid.uuid4())
        self.mac = stub_utils.get_mac()
        self.suffix = self.id[:11]
        if interface:
            self.interface = interface
        else:
            self.interface = prefix + self.suffix
        addrs = []
        for addr in addresses:
            if "." in addr:
                addrs.append({'gateway': "1.2.3.1", 'addr': addr})
            else:
                addrs.append({'gateway': "2001::1234", 'addr': addr})

        self.create_req = { 'type': "ENDPOINTCREATED",
                            'endpoint_id': self.id,
                            'resync_id': resync_id,
                            'issued': str(futils.time_ms()),
                            'mac': self.mac,
                            'state': Endpoint.STATE_ENABLED,
                            'addrs': addrs }

        if interface:
            self.create_req['interface_id'] = self.interface

        self.destroy_req = { 'type': "ENDPOINTDESTROYED",
                             'endpoint_id': self.id,
                             'issued': futils.time_ms() }

        log.debug("Create test endpoint %s", self.id)

        stub_devices.add_interface(stub_devices.TapInterface(self.interface))
