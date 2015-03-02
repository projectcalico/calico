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
openstack.test.test_plugin
~~~~~~~~~~~

Unit test for the Calico/OpenStack Plugin.
"""
import mock
import sys
import unittest
import eventlet
import eventlet.queue
import traceback
import json
import inspect
from eventlet.support import greenlets as greenlet

if 'zmq' in sys.modules:
    del sys.modules['zmq']
sys.modules['neutron'] = m_neutron = mock.Mock()
sys.modules['neutron.common'] = m_neutron.common
sys.modules['neutron.openstack'] = m_neutron.openstack
sys.modules['neutron.openstack.common'] = m_neutron.openstack.common
sys.modules['neutron.plugins'] = m_neutron.plugins
sys.modules['neutron.plugins.ml2'] = m_neutron.plugins.ml2
sys.modules['neutron.plugins.ml2.drivers'] = m_neutron.plugins.ml2.drivers
sys.modules['oslo'] = m_oslo = mock.Mock()
sys.modules['oslo.config'] = m_oslo.config
sys.modules['time'] = m_time = mock.Mock()


# Define a stub class, that we will use as the base class for
# CalicoMechanismDriver.
class DriverBase(object):
    def __init__(self, agent_type, vif_type, vif_details):
        pass

# Replace Neutron's SimpleAgentMechanismDriverBase - which is the base class
# that CalicoMechanismDriver inherits from - with this stub class.
m_neutron.plugins.ml2.drivers.mech_agent.SimpleAgentMechanismDriverBase = \
    DriverBase

import calico.openstack.mech_calico as mech_calico

REAL_EVENTLET_SLEEP_TIME = 0.2

# Test variation flags.
NO_HEARTBEAT_RESPONSE = 1
NO_ENDPOINT_RESPONSE = 2

# Value used to indicate 'timeout' in poll and sleep processing.
TIMEOUT_VALUE = object()


class TestPlugin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        global real_eventlet_sleep
        global real_eventlet_spawn

        # Replacement for eventlet.sleep: sleep for some simulated passage of
        # time (as directed by simulated_time_advance), instead of for real
        # elapsed time.
        def simulated_time_sleep(secs):

            # Create a new queue.
            queue = eventlet.Queue(1)
            queue.stack = inspect.stack()[1][3]

            # Add it to the dict of sleepers, together with the waking up time.
            sleepers[queue] = current_time + secs

            print "T=%s: %s: Start sleep for %ss until T=%s" % (
                current_time, queue.stack, secs, sleepers[queue]
            )

            # Do a zero time real sleep, to allow other threads to run.
            real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

            # Block until something is posted to the queue.
            ignored = queue.get(True)

            # Wake up.
            return None

        # Replacement for eventlet.spawn: track spawned threads so that we can
        # kill them all when a test case ends.
        def simulated_spawn(*args):

            # Do the real spawn.
            thread = real_eventlet_spawn(*args)

            # Remember this thread.
            threads.append(thread)

            # Also return it.
            return thread

        # Hook sleeping.  We must only do this once; hence it is in setUpClass
        # rather than in setUp.
        real_eventlet_sleep = eventlet.sleep
        mech_calico.eventlet.sleep = simulated_time_sleep

        # Similarly hook spawning.
        real_eventlet_spawn = eventlet.spawn
        mech_calico.eventlet.spawn = simulated_spawn

    @classmethod
    def tearDownClass(cls):

        # Restore the real eventlet.sleep.
        mech_calico.eventlet.sleep = real_eventlet_sleep

    # Setup for explicit test code control of all operations on 0MQ sockets.
    def setUp_sockets(self):

        # Set of addresses that we have sockets bound to.
        self.sockets = set()

        # When a socket is created, print a message to say so, and hook its
        # bind method.
        def socket_created(tp):
            print "New socket type %s" % tp

            # Create a new mock socket.
            socket = mock.Mock()

            # Hook its bind and connect methods, so we can remember the address
            # that it binds or connects to.
            socket.bind.side_effect = make_socket_bound(socket)
            socket.connect.side_effect = make_socket_connect(socket)

            # Create a queue that we can use to deliver messages to be received
            # on this socket.
            socket.rcv_queue = eventlet.Queue(1)

            # Hook the socket's recv_multipart and poll methods, to wait on
            # this queue.
            socket.recv_multipart.side_effect = make_recv('multipart', socket)
            socket.recv_json.side_effect = make_recv('json', socket)
            socket.poll.side_effect = make_poll(socket)

            # Add this to the test code's list of known sockets.
            self.sockets.add(socket)

            return socket

        # When a socket binds to an address, remember that address.
        def make_socket_bound(socket):

            def socket_bound(addr):
                print "Socket %s bound to %s" % (socket, addr)

                # Remember the address.
                socket.bound_address = addr

                return None

            return socket_bound

        # When a socket connects to an address, remember that address.
        def make_socket_connect(socket):

            def socket_connect(addr):
                print "Socket %s connected to %s" % (socket, addr)

                # Remember the address.
                socket.connected_address = addr

                return None

            return socket_connect

        # When socket calls recv_multipart or recv_json, block on the socket's
        # receive queue.
        def make_recv(name, socket):

            def recv(flags=0, *args):
                print "Socket %s recv_%s..." % (socket, name)

                # Block until there's something to receive, and then get that.
                try:
                    msg = socket.rcv_queue.get(not (flags &
                                                    mech_calico.zmq.NOBLOCK))
                except eventlet.queue.Empty:
                    raise mech_calico.Again()

                # Return that.
                return msg

            return recv

        # When socket calls poll, block on the socket's receive queue.
        def make_poll(socket):

            def poll(ms):
                print "Socket %s poll for %sms..." % (socket, ms)

                # Add this socket's receive queue to the set of current
                # sleepers.
                socket.rcv_queue.stack = inspect.stack()[1][3]
                sleepers[socket.rcv_queue] = current_time + ms / 1000

                # Block until there's something added to the queue.
                msg = socket.rcv_queue.get(True)

                # If what was added was not the timeout indication, put it back
                # on the queue, for a following receive call.
                if msg is not TIMEOUT_VALUE:
                    socket.rcv_queue.put_nowait(msg)

                real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

                # Return nothing.
                return None

            return poll

        # Intercept 0MQ socket creations, so that we can hook all of the
        # operations on sockets, using the methods above.
        mech_calico.zmq.Context = mock.Mock()
        self.zmq_context = mech_calico.zmq.Context.return_value
        self.zmq_context.socket.side_effect = socket_created

    # Setup to intercept and display logging by the code under test.
    def setUp_logging(self):

        # Print logs to stdout.
        def log_info(msg):
            print "       INFO %s" % msg
            return None

        def log_debug(msg):
            print "       DEBUG %s" % msg
            return None

        def log_warn(msg):
            print "       WARN %s" % msg
            return None

        def log_error(msg):
            print "       ERROR %s" % msg
            return None

        def log_exception(msg):
            print "       EXCEPTION %s" % msg
            if sys.exc_type is not greenlet.GreenletExit:
                traceback.print_exc()
            return None

        # Hook logging.
        mech_calico.LOG = mock.Mock()
        mech_calico.LOG.info.side_effect = log_info
        mech_calico.LOG.debug.side_effect = log_debug
        mech_calico.LOG.warn.side_effect = log_warn
        mech_calico.LOG.error.side_effect = log_error
        mech_calico.LOG.exception.side_effect = log_exception

    # Setup to intercept sleep calls made by the code under test, and hence to
    # (i) control when those expire, and (ii) allow time to appear to pass (to
    # the code under test) without actually having to wait for that time.
    def setUp_time(self):

        global current_time
        global sleepers
        global threads

        # Reset the simulated time (in seconds) that has passed since the
        # beginning of the test.
        current_time = 0

        # Make time.time() return current_time.
        m_time.time.side_effect = lambda: current_time

        # Reset the dict of current sleepers.  In each dict entry, the key is
        # an eventlet.Queue object and the value is the time at which the sleep
        # should complete.
        sleepers = {}

        threads = []

        print "\nTEST CASE: %s" % self.id()

    # Method for the test code to call when it wants to advance the simulated
    # time.
    def simulated_time_advance(self, secs):

        global current_time

        while (secs > 0):
            print "T=%s: Want to advance by %s" % (current_time, secs)

            # Determine the time to advance to in this iteration: either the
            # full time that we've been asked for, or the time at which the
            # next sleeper should wake up, whichever of those is earlier.
            wake_up_time = current_time + secs
            for queue in sleepers.keys():
                if sleepers[queue] < wake_up_time:
                    # This sleeper will wake up before the time that we've been
                    # asked to advance to.
                    wake_up_time = sleepers[queue]

            # Check if we're about to advance past any exact multiples of
            # HEARTBEAT_SEND_INTERVAL_SECS.
            num_acl_pub_heartbeats = (
                int(wake_up_time / mech_calico.HEARTBEAT_SEND_INTERVAL_SECS) -
                int(current_time / mech_calico.HEARTBEAT_SEND_INTERVAL_SECS)
            )

            # Advance to the determined time.
            secs -= (wake_up_time - current_time)
            current_time = wake_up_time
            print "T=%s" % current_time

            # Wake up all sleepers that should now wake up.
            for queue in sleepers.keys():
                if sleepers[queue] <= current_time:
                    print "T=%s >= %s: %s: Wake up!" % (current_time,
                                                        sleepers[queue],
                                                        queue.stack)
                    del sleepers[queue]
                    queue.put_nowait(TIMEOUT_VALUE)

            # Allow woken (and possibly other) threads to run.
            real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

            # Handle any ACL HEARTBEAT publications.
            for i in range(num_acl_pub_heartbeats):
                print "Handle ACL HEARTBEAT publication"
                pub = {'type': 'HEARTBEAT',
                       'issued': current_time * 1000}
                self.acl_pub_socket.send_multipart.assert_called_once_with(
                    ['networkheartbeat'.encode('utf-8'),
                     json.dumps(pub).encode('utf-8')])
                self.acl_pub_socket.send_multipart.reset_mock()

    # Setup before each test case (= each method below whose name begins with
    # "test").
    def setUp(self):

        # Normally do not provide bind_host config.
        m_oslo.config.cfg.CONF.bind_host = None

        # Setup to control 0MQ socket operations.
        self.setUp_sockets()

        # Setup to control logging.
        self.setUp_logging()

        # Setup to control the passage of time.
        self.setUp_time()

        # Create an instance of CalicoMechanismDriver.
        self.driver = mech_calico.CalicoMechanismDriver()

    # Tear down after each test case.
    def tearDown(self):

        print "\nClean up remaining green threads..."

        for thread in threads:
            thread.kill()

    # Check that a socket is now bound to a specified address and port, and
    # return that socket.
    def assert_get_bound_socket(self, addr, port):
        bound_sockets = set(socket for socket in self.sockets
                            if socket.bound_address == ("tcp://%s:%s" %
                                                        (addr, port)))
        self.assertEqual(len(bound_sockets), 1)
        return bound_sockets.pop()

    # Test binding to a specific IP address.
    def test_bind_host(self):

        # Provide bind_host config.
        ip_addr = '192.168.1.1'
        m_oslo.config.cfg.CONF.bind_host = ip_addr

        # Tell the driver to initialize.
        self.driver.initialize()

        # Check that sockets are bound to the specific IP address.
        self.felix_router_socket = self.assert_get_bound_socket(ip_addr, 9901)
        self.acl_get_socket = self.assert_get_bound_socket(ip_addr, 9903)
        self.acl_pub_socket = self.assert_get_bound_socket(ip_addr, 9904)

    # Mainline test.
    def test_mainline(self):

        # Start of day processing: initialization and socket binding.
        self.start_of_day()

        # Connect a Felix instance.
        self.felix_connect()

        # Further mainline steps that we haven't actually implemented yet.
        self.acl_connect()
        self.call_noop_entry_points()
        self.new_endpoint()
        self.endpoint_update()
        self.sg_rule_update()
        self.endpoint_deletion()

    # Test when plugin sends a HEARTBEAT request and Felix does not respond
    # within HEARTBEAT_RESPONSE_TIMEOUT.
    def test_no_heartbeat_response(self):

        # Start of day processing: initialization and socket binding.
        self.start_of_day()

        # Connect a Felix instance.
        self.felix_connect(flags=set([NO_HEARTBEAT_RESPONSE]))
        self.sockets.remove(self.felix_endpoint_socket)

        # Check that it works for Felix to connect again after the plugin has
        # cleaned up following that non-response.
        self.felix_connect()

    # Test when plugin sends an ENDPOINT* request and Felix does not respond
    # within ENDPOINT_RESPONSE_TIMEOUT.
    def test_no_endpoint_response(self):

        # Start of day processing: initialization and socket binding.
        self.start_of_day()

        # Connect a Felix instance.
        self.felix_connect()

        # Process a new endpoint, but don't send in the ENDPOINTCREATED
        # response.
        self.new_endpoint(flags=set([NO_ENDPOINT_RESPONSE]))
        self.sockets.remove(self.felix_endpoint_socket)

        # Let time pass to allow the felix_heartbeat_thread for the old
        # connection to die.  It's a bug that we need to do this: Github issue
        # #224.
        self.simulated_time_advance(40)

        # Connect the Felix instance again.
        self.felix_connect()

        # Now process the new endpoint successfully.
        self.new_endpoint()

    def start_of_day(self):
        # Tell the driver to initialize.
        self.driver.initialize()

        # Check that there's a socket bound to port 9901, and get it.
        self.felix_router_socket = self.assert_get_bound_socket('*', 9901)
        print "Felix router socket is %s" % self.felix_router_socket

        # Check that there's a socket bound to port 9903, and get it.
        self.acl_get_socket = self.assert_get_bound_socket('*', 9903)
        print "ACL GET socket is %s" % self.acl_get_socket

        # Check that there's a socket bound to port 9904, and get it.
        self.acl_pub_socket = self.assert_get_bound_socket('*', 9904)
        print "ACL PUB socket is %s" % self.acl_pub_socket

    def felix_connect(self, **kwargs):
        # Hook the Neutron database.
        self.db = mech_calico.manager.NeutronManager.get_plugin()
        self.db_context = mech_calico.ctx.get_admin_context()
        self.db.get_ports.return_value = []

        # Get test variation flags.
        flags = kwargs.get('flags', set())

        # Send a RESYNCSTATE.
        resync = {'type': 'RESYNCSTATE',
                  'resync_id': 'resync#1',
                  'issued': current_time * 1000,
                  'hostname': 'felix-host-1'}
        self.felix_router_socket.rcv_queue.put_nowait(
            ['felix-1',
             '',
             json.dumps(resync).encode('utf-8')])
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        # Check DB got create_or_update_agent call.
        self.db.create_or_update_agent.assert_called_once_with(
            self.db_context,
            {'agent_type': mech_calico.AGENT_TYPE_FELIX,
             'binary': '',
             'host': 'felix-host-1',
             'topic': mech_calico.constants.L2_AGENT_TOPIC,
             'start_flag': True})
        self.db.create_or_update_agent.reset_mock()

        # Check RESYNCSTATE response was sent.
        self.felix_router_socket.send_multipart.assert_called_once_with(
            ['felix-1',
             '',
             json.dumps({'type': 'RESYNCSTATE',
                         'endpoint_count': 0,
                         'interface_prefix': 'tap',
                         'rc': 'SUCCESS',
                         'message': 'Здра́вствуйте!'}).encode('utf-8')])
        self.felix_router_socket.send_multipart.reset_mock()

        # Send HEARTBEAT from Felix and check for response.
        self.felix_router_socket.rcv_queue.put_nowait(
            ['felix-1',
             '',
             json.dumps({'type': 'HEARTBEAT'}).encode('utf-8')])
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
        self.felix_router_socket.send_multipart.assert_called_once_with(
            ['felix-1',
             '',
             json.dumps({'type': 'HEARTBEAT'}).encode('utf-8')])
        self.felix_router_socket.send_multipart.reset_mock()

        # Get the socket that the plugin used to connect back to Felix.
        connected_sockets = set(socket for socket in self.sockets
                                if (socket.connected_address ==
                                    "tcp://felix-host-1:9902"))
        self.assertEqual(len(connected_sockets), 1)
        self.felix_endpoint_socket = connected_sockets.pop()
        print "Felix endpoint socket is %s" % self.felix_endpoint_socket

        # Need another yield here, apparently, to allow felix_heartbeat_thread
        # to start running.
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        # Receive HEARTBEAT to Felix from the plugin, and send response.
        self.simulated_time_advance(30)
        self.felix_endpoint_socket.send_json.assert_called_once_with(
            {'type': 'HEARTBEAT'},
            mech_calico.zmq.NOBLOCK)
        self.felix_endpoint_socket.send_json.reset_mock()

        if NO_HEARTBEAT_RESPONSE in flags:
            # Advance time by more than HEARTBEAT_RESPONSE_TIMEOUT.
            self.simulated_time_advance((mech_calico.HEARTBEAT_RESPONSE_TIMEOUT
                                         / 1000) + 1)

            # The plugin now cleans up its Felix socket.
            return

        self.felix_endpoint_socket.rcv_queue.put_nowait(
            {'type': 'HEARTBEAT'})
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        # Check DB got create_or_update_agent call.
        self.db.create_or_update_agent.assert_called_once_with(
            self.db_context,
            {'agent_type': mech_calico.AGENT_TYPE_FELIX,
             'binary': '',
             'host': 'felix-host-1',
             'topic': mech_calico.constants.L2_AGENT_TOPIC})
        self.db.create_or_update_agent.reset_mock()

        # Yield to allow anything pending on other threads to come out.
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

    def acl_connect(self):
        # ACL Manager connection.
        #
        # - sim-DB: Prep response to next get_security_groups query, returning
        #  the default SG.  Prep null response to next
        #  _get_port_security_group_bindings call.
        #
        # - sim-ACLM: Connect to PLUGIN_ACLGET_PORT, send GETGROUPS, check get
        #  GETGROUPS response.  Check get GROUPUPDATE publication describing
        #  default SG.
        #
        # - sim-ACLM: Send HEARTBEAT, check get HEARTBEAT response.
        #
        # - sim-ACLM: Wait for HEARTBEAT_SEND_INTERVAL_SECS, check get
        #   HEARTBEAT, send HEARTBEAT response.
        pass

    def call_noop_entry_points(self):
        # Mechanism driver entry points that are currently implemented as
        # no-ops (because Calico function does not need them).
        #
        # - sim-ML2: Call update_subnet_postcommit, update_network_postcommit,
        #   delete_subnet_postcommit, delete_network_postcommit,
        #   create_network_postcommit, create_subnet_postcommit,
        #   update_network_postcommit, update_subnet_postcommit.
        pass

    # New endpoint processing.
    def new_endpoint(self, **kwargs):

        # Get test variation flags.
        flags = kwargs.get('flags', set())

        # Simulate ML2 asking the driver if it can handle a port.
        self.assertTrue(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'flat'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

        # Prep response to next get_subnet call.
        self.db.get_subnet.return_value = {'gateway_ip': '10.65.0.1'}

        # Simulate ML2 notifying creation of the new port.
        context = mock.Mock()
        context._port = {'binding:host_id': 'felix-host-1',
                         'id': 'DEADBEEF-1234-5678',
                         'device_owner': 'compute:nova',
                         'fixed_ips': [{'subnet_id': '10.65.0/24',
                                        'ip_address': '10.65.0.2'}],
                         'mac_address': '00:11:22:33:44:55',
                         'admin_state_up': True}

        if NO_ENDPOINT_RESPONSE in flags:
            # Expect create_port_postcommit to throw a FelixUnavailable
            # exception.
            real_eventlet_spawn(
                lambda: self.assertRaises(mech_calico.FelixUnavailable,
                                          self.driver.create_port_postcommit,
                                          (context)))
        else:
            # No exception expected.
            real_eventlet_spawn(
                lambda: self.driver.create_port_postcommit(context))

        # Yield to allow that new thread to run.
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        # Check ENDPOINTCREATED request is sent to Felix.  Simulate Felix
        # responding successfully.
        self.felix_endpoint_socket.send_json.assert_called_once_with(
            {'mac': '00:11:22:33:44:55',
             'addrs': [{'properties': {'gr': False},
                        'addr': '10.65.0.2',
                        'gateway': '10.65.0.1'}],
             'endpoint_id': 'DEADBEEF-1234-5678',
             'interface_name': 'tapDEADBEEF-12',
             'issued': mock.ANY,
             'resync_id': None,
             'type': 'ENDPOINTCREATED',
             'state': 'enabled'},
            mech_calico.zmq.NOBLOCK)
        self.felix_endpoint_socket.send_json.reset_mock()

        if NO_ENDPOINT_RESPONSE in flags:
            # Advance time by more than ENDPOINT_RESPONSE_TIMEOUT.
            self.simulated_time_advance((mech_calico.ENDPOINT_RESPONSE_TIMEOUT
                                         / 1000) + 1)

            # The plugin now cleans up its Felix socket.
            return

        self.felix_endpoint_socket.rcv_queue.put_nowait(
            {'type': 'ENDPOINTCREATED',
             'rc': 'SUCCESS',
             'message': ''})
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
        real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        # Check get update_port_status call, indicating port active.
        self.db.update_port_status.assert_called_once_with(
            context._plugin_context,
            context._port['id'],
            mech_calico.constants.PORT_STATUS_ACTIVE)
        self.db.update_port_status.reset_mock()

        # Prep appropriate responses for next get_security_group,
        # _get_port_security_group_bindings and get_port calls.
        self.db.get_security_group.return_value = {
            'id': 'SG-1',
            'security_group_rules': []
        }
        self.db._get_port_security_group_bindings.return_value = [
            {'port_id': 'DEADBEEF-1234-5678'}
        ]
        self.db.get_port.return_value = context._port

        # Call security_groups_member_updated with default SG ID.
        self.db.notifier.security_groups_member_updated(context, ['SG-1'])

        # Check get GROUPUPDATE publication indicating port added to default SG
        # ID.
        pub = {'rules': {'inbound': [],
                         'outbound': [],
                         'outbound_default': 'deny',
                         'inbound_default': 'deny'},
               'group': 'SG-1',
               'type': 'GROUPUPDATE',
               'members': {'DEADBEEF-1234-5678': ['10.65.0.2']},
               'issued': current_time * 1000}

        # Unpack the last self.acl_pub_socket.send_multipart call, to check
        # that its args were as expected.  It doesn't work to check the
        # arguments directly using assert_called_once_with(...), because
        # variation is possible when a dict such as 'pub' is represented as a
        # string.
        kall = self.acl_pub_socket.send_multipart.call_args
        assert kall is not None
        args, kwargs = kall
        assert len(args) == 1
        assert len(args[0]) == 2
        assert args[0][0].decode('utf-8') == 'groups'
        assert json.loads(args[0][1].decode('utf-8')) == pub
        self.acl_pub_socket.send_multipart.reset_mock()

    def endpoint_update(self):
        # Endpoint update processing.
        #
        # - sim-DB: Prep response to next get_subnet call.
        #
        # - sim-ML2: Call update_port_postcommit for an endpoint port with
        #   host_id matching sim-Felix.
        #
        # - sim-Felix: Check get ENDPOINTUPDATED.  Send successful response.
        pass

    def sg_rule_update(self):
        # SG rules update processing.
        #
        # - sim-DB: Prep appropriate responses for next get_security_group,
        #   _get_port_security_group_bindings and get_port calls.
        #
        # - sim-ML2: Call security_groups_rule_updated with default SG ID.
        #
        # - sim-ACLM: Check get GROUPUPDATE publication indicating updated
        #   rules.
        pass

    def endpoint_deletion(self):
        # Endpoint deletion processing.
        #
        # - sim-ML2: Call delete_port_postcommit for an endpoint port with
        #   host_id matching sim-Felix.
        #
        # - sim-Felix: Check get ENDPOINTDESTROYED.  Send successful response.
        #
        # - sim-DB: Prep appropriate responses for next get_security_group,
        #   _get_port_security_group_bindings and get_port calls.
        #
        # - sim-ML2: Call security_groups_member_updated with default SG ID.
        #
        # - sim-ACLM: Check get GROUPUPDATE publication indicating port removed
        #   from default SG ID.
        pass

    def test_timing_new_endpoint(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Repeat mainline test with variation: for a new endpoint, sim-ML2
        # calls security_groups_member_updated before create_port_postcommit,
        # instead of after it.

    def test_timing_endpoint_deletion(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Repeat mainline test with variation: for an endpoint being deleted,
        # sim-ML2 calls security_groups_member_updated before
        # delete_port_postcommit, instead of after it.

    def test_multiple_2(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Connect two Felix instances.  Create multiple endpoints, with host-id
        # selecting one of the available Felices.
        #
        # Check plugin sends HEARTBEATs to both instances and correctly
        # processes HEARTBEATs from both instances.
        #
        # Create lots of endpoints, spread across the two instances.  Then get
        # both instances to send RESYNCSTATE at the same time.

    def test_multiple_10(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Connect 10 Felix instances.  Create 100 endpoints, 10 for each
        # instance.  Put each endpoint into one of 10 SGs, so that each Felix
        # has one endpoint in each of the 10 SGs.  Get all 10 instances to send
        # RESYNCSTATE in series (without any delay between them).  Send
        # GETGROUPS from ACL manager, check that all SGs are correctly resent
        # to ACL manager.

    # Tests of partners disconnecting and/or connectivity trouble...
    #
    # Test the following possible errors to various socket operations. These
    # all represent different manifestations of networking connectivity
    # trouble.

    def test_felix_router_addr_in_use(self):

        # Operations on the PLUGIN_ENDPOINT_PORT ROUTER socket.
        #
        # : self.felix_router_socket = self.zmq_context.socket(zmq.ROUTER)
        #
        # - 'Address in use' error when binding to PLUGIN_ENDPOINT_PORT.
        pass

    def test_acl_get_addr_in_use(self):

        # Operations on the PLUGIN_ACLGET_PORT ROUTER socket.
        #
        # : self.acl_get_socket = self.zmq_context.socket(zmq.ROUTER)
        #
        # - 'Address in use' error when binding to PLUGIN_ACLGET_PORT.
        pass

    def test_acl_pub_addr_in_use(self):

        # Operations on the PLUGIN_ACLPUB_PORT PUB socket.
        #
        # : self.acl_pub_socket = self.zmq_context.socket(zmq.PUB)
        #
        # - 'Address in use' error when binding to PLUGIN_ACLPUB_PORT.
        pass

    def test_felix_eagain_snd_endpoint(self):

        # Operations on the FELIX_ENDPOINT_PORT REQ socket.
        #
        # : sock = self.zmq_context.socket(zmq.REQ)
        # : sock.setsockopt(zmq.LINGER, 0)
        # : sock.connect("tcp://%s:%s" % (hostname, FELIX_ENDPOINT_PORT))
        # : self.felix_peer_sockets[hostname] = sock
        #
        # - 'EWOULDBLOCK' error when sending ENDPOINT* request.
        pass

    def test_felix_eagain_rcv_endpoint(self):

        # - 'EWOULDBLOCK' error when receiving ENDPOINT* response.
        pass

    def test_felix_eagain_snd_heartbeat(self):

        # - 'EWOULDBLOCK' error when sending HEARTBEAT request.
        pass

    def test_felix_eagain_rcv_heartbeat(self):

        # - 'EWOULDBLOCK' error when receiving HEARTBEAT response.
        pass

    def test_connectivity_blips(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Test the following scenarios, to check that plugin processing is
        # continuous and correct across connectivity blips.
        #
        # - Connect a Felix, and process a new endpoint for that Felix.
        #   Simulate disconnection and reconnection, in the form of a
        #   RESYNCSTATE on new connection but with same hostname.  Check that
        #   the existing endpoint is sent on the new connection.  Check that
        #   heartbeats occur as normal on the new connection.
        #
        # - Add another new endpoint for same hostname, and check it is
        #   processed normally and notified on the new connection.
        #
        # - Simulate disconnect and reconnect again, and check that both
        #   existing endpoints are notified on the new active connection (#3),
        #   after the new RESYNCSTATE.

    def test_no_felix_new_endpoint(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # ** Error cases
        #
        # Do new endpoint processing when required Felix is not available.
        # Check that sim-ML2 sees a FelixUnavailable exception from its
        # create_port_postcommit call.
        #
        # Call create_port_postcommit again with host-id changed to match a
        # Felix that _is_ available.  Check that new endpoint processing then
        # proceeds normally.

    def test_no_felix_endpoint_update(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Do endpoint update processing when required Felix is not available.
        # Check that sim-ML2 sees a FelixUnavailable exception from its
        # update_port_postcommit call.

    def test_no_felix_endpoint_deleted(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # Do endpoint deletion processing when required Felix is not available.
        # Check that sim-ML2 sees a FelixUnavailable exception from its
        # delete_port_postcommit call.

    def test_code_coverage(self):

        # Tell the driver to initialize.
        self.driver.initialize()

        # ** Code coverage
        #
        # After implementing and executing all of the above, review code
        # coverage and add further tests for any mech_calico.py lines that have
        # not yet been covered.  (Or else persuade ourselves that we don't
        # actually need those lines, and delete them.)
