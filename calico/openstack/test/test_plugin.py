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
import logging
import mock
import socket
import sys
import time
import unittest
import uuid
import eventlet
import traceback
import json
import inspect

if 'zmq' in sys.modules: del sys.modules['zmq']
sys.modules['neutron'] = m_neutron = mock.Mock()
sys.modules['neutron.common'] = m_neutron.common
sys.modules['neutron.openstack'] = m_neutron.openstack
sys.modules['neutron.openstack.common'] = m_neutron.openstack.common
sys.modules['neutron.plugins'] = m_neutron.plugins
sys.modules['neutron.plugins.ml2'] = m_neutron.plugins.ml2
sys.modules['neutron.plugins.ml2.drivers'] = m_neutron.plugins.ml2.drivers

#*****************************************************************************#
#* Define a stub class, that we will use as the base class for               *#
#* CalicoMechanismDriver.                                                    *#
#*****************************************************************************#
class DriverBase(object):
    def __init__(self, agent_type, vif_type, vif_details):
        pass

#*****************************************************************************#
#* Replace Neutron's SimpleAgentMechanismDriverBase - which is the base      *#
#* class that CalicoMechanismDriver inherits from - with this stub class.    *#
#*****************************************************************************#
m_neutron.plugins.ml2.drivers.mech_agent.SimpleAgentMechanismDriverBase = DriverBase

import calico.openstack.mech_calico as mech_calico

REAL_EVENTLET_SLEEP_TIME = 0.2

class TestPlugin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    #*************************************************************************#
    #* Setup for explicit test code control of all operations on 0MQ         *#
    #* sockets.                                                              *#
    #*************************************************************************#
    def setUp_sockets(self):

        #*********************************************************************#
        #* Set of addresses that we have sockets bound to.                   *#
        #*********************************************************************#
        self.sockets = set()

        #*********************************************************************#
        #* When a socket is created, print a message to say so, and hook its *#
        #* bind method.                                                      *#
        #*********************************************************************#
        def socket_created(tp):
            print "New socket type %s" % tp

            #*****************************************************************#
            #* Create a new mock socket.                                     *#
            #*****************************************************************#
            socket = mock.Mock()

            #*****************************************************************#
            #* Hook its bind and connect methods, so we can remember the     *#
            #* address that it binds or connects to.                         *#
            #*****************************************************************#
            socket.bind.side_effect = make_socket_bound(socket)
            socket.connect.side_effect = make_socket_connect(socket)

            #*****************************************************************#
            #* Create a queue that we can use to deliver messages to be      *#
            #* received on this socket.                                      *#
            #*****************************************************************#
            socket.rcv_queue = eventlet.Queue(1)

            #*****************************************************************#
            #* Hook the socket's recv_multipart and poll methods, to wait on *#
            #* this queue.                                                   *#
            #*****************************************************************#
            socket.recv_multipart.side_effect = make_recv('multipart', socket)
            socket.recv_json.side_effect = make_recv('json', socket)
            socket.poll.side_effect = make_poll(socket)

            #*****************************************************************#
            #* Add this to the test code's list of known sockets.            *#
            #*****************************************************************#
            self.sockets |= {socket}

            return socket

        #*********************************************************************#
        #* When a socket binds to an address, remember that address.         *#
        #*********************************************************************#
        def make_socket_bound(socket):

            def socket_bound(addr):
                print "Socket %s bound to %s" % (socket, addr)

                #*************************************************************#
                #* Remember the address.                                     *#
                #*************************************************************#
                socket.bound_address = addr

                return None

            return socket_bound

        #*********************************************************************#
        #* When a socket connects to an address, remember that address.      *#
        #*********************************************************************#
        def make_socket_connect(socket):

            def socket_connect(addr):
                print "Socket %s connected to %s" % (socket, addr)

                #*************************************************************#
                #* Remember the address.                                     *#
                #*************************************************************#
                socket.connected_address = addr

                return None

            return socket_connect

        #*********************************************************************#
        #* When socket calls recv_multipart or recv_json, block on the       *#
        #* socket's receive queue.                                           *#
        #*********************************************************************#
        def make_recv(name, socket):

            def recv(*args):
                print "Socket %s recv_%s..." % (socket, name)

                #*************************************************************#
                #* Block until there's something to receive, and then get    *#
                #* that.                                                     *#
                #*************************************************************#
                msg = socket.rcv_queue.get(True)

                #*************************************************************#
                #* Return that.                                              *#
                #*************************************************************#
                return msg

            return recv

        #*********************************************************************#
        #* When socket calls poll, block on the socket's receive queue.      *#
        #*********************************************************************#
        def make_poll(socket):

            def poll(ms):
                print "Socket %s poll for %sms..." % (socket, ms)

                #*************************************************************#
                #* Block until there's something to receive, and then get    *#
                #* that.                                                     *#
                #*************************************************************#
                msg = socket.rcv_queue.get(True, ms / 1000)

                #*************************************************************#
                #* Get the message back on the queue, for a following        *#
                #* receive call.                                             *#
                #*************************************************************#
                socket.rcv_queue.put_nowait(msg)
                self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

                #*************************************************************#
                #* Return nothing.                                           *#
                #*************************************************************#
                return None

            return poll

        #*********************************************************************#
        #* Intercept 0MQ socket creations, so that we can hook all of the    *#
        #* operations on sockets, using the methods above.                   *#
        #*********************************************************************#
        mech_calico.zmq.Context = mock.Mock()
        self.zmq_context = mech_calico.zmq.Context.return_value
        self.zmq_context.socket.side_effect = socket_created

    #*************************************************************************#
    #* Setup to intercept and display logging by the code under test.        *#
    #*************************************************************************#
    def setUp_logging(self):

        #*********************************************************************#
        #* Print logs to stdout.                                             *#
        #*********************************************************************#
        def log_info(msg):
            print ">>>>>>>INFO %s" % msg
            return None
        def log_debug(msg):
            print ">>>>>>DEBUG %s" % msg
            return None
        def log_warn(msg):
            print ">>>>>>>WARN %s" % msg
            return None
        def log_exception(msg):
            print ">>EXCEPTION %s" % msg
            traceback.print_exc()
            return None

        #*********************************************************************#
        #* Hook logging.                                                     *#
        #*********************************************************************#
        mech_calico.LOG = mock.Mock()
        mech_calico.LOG.info.side_effect = log_info
        mech_calico.LOG.debug.side_effect = log_debug
        mech_calico.LOG.warn.side_effect = log_warn
        mech_calico.LOG.exception.side_effect = log_exception

    #*************************************************************************#
    #* Setup to intercept sleep calls made by the code under test, and hence *#
    #* to (i) control when those expire, and (ii) allow time to appear to    *#
    #* pass (to the code under test) without actually having to wait for     *#
    #* that time.                                                            *#
    #*************************************************************************#
    def setUp_time(self):

        #*********************************************************************#
        #* The simulated time (in seconds) that has passed since the         *#
        #* beginning of the test.                                            *#
        #*********************************************************************#
        self.current_time = 0

        #*********************************************************************#
        #* Dict of current sleepers.  In each dict entry, the key is an      *#
        #* eventlet.Queue object and the value is the time at which the      *#
        #* sleep should complete.                                            *#
        #*********************************************************************#
        self.sleepers = {}

        #*********************************************************************#
        #* Sleep for some simulated time.                                    *#
        #*********************************************************************#
        def simulated_time_sleep(secs):

            #*****************************************************************#
            #* Do a zero time real sleep, to allow other threads to run.     *#
            #*****************************************************************#
            self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

            #*****************************************************************#
            #* Create a new queue.                                           *#
            #*****************************************************************#
            queue = eventlet.Queue(1)
            queue.stack = inspect.stack()[1][3]

            print "%s: Start sleep for %ss" % (queue.stack, secs)

            #*****************************************************************#
            #* Add it to the dict of sleepers, together with the waking up   *#
            #* time.                                                         *#
            #*****************************************************************#
            self.sleepers[queue] = self.current_time  + secs

            #*****************************************************************#
            #* Block until something is posted to the queue.                 *#
            #*****************************************************************#
            ignored = queue.get(True)

            #*****************************************************************#
            #* Wake up.                                                      *#
            #*****************************************************************#
            return None

        #*********************************************************************#
        #* Hook sleeping.                                                    *#
        #*********************************************************************#
        self.real_eventlet_sleep = eventlet.sleep
        mech_calico.eventlet.sleep = simulated_time_sleep

    #*************************************************************************#
    #* Method for the test code to call when it wants to advance the         *#
    #* simulated time.                                                       *#
    #*************************************************************************#
    def simulated_time_advance(self, secs):

        while (secs > 0):
            print "Time %s, want to advance by %s" % (self.current_time,
                                                      secs)

            #*****************************************************************#
            #* Determine the time to advance to in this iteration: either    *#
            #* the full time that we've been asked for, or the time at which *#
            #* the next sleeper should wake up, whichever of those is        *#
            #* earlier.                                                      *#
            #*****************************************************************#
            wake_up_time = self.current_time + secs
            for queue in self.sleepers.keys():
                if self.sleepers[queue] < wake_up_time:
                    #*********************************************************#
                    #* This sleeper will wake up before the time that we've  *#
                    #* been asked to advance to.                             *#
                    #*********************************************************#
                    wake_up_time = self.sleepers[queue]

            #*****************************************************************#
            #* Advance to the determined time.                               *#
            #*****************************************************************#
            secs -= (wake_up_time - self.current_time)
            self.current_time = wake_up_time

            #*****************************************************************#
            #* Wake up all sleepers that should now wake up.                 *#
            #*****************************************************************#
            for queue in self.sleepers.keys():
                if self.sleepers[queue] >= self.current_time:
                    print "Wake up one sleeper: %s" % queue.stack
                    del self.sleepers[queue]
                    queue.put_nowait('Wake up!')
                    
            #*****************************************************************#
            #* Allow woken (and possibly other) threads to run.              *#
            #*****************************************************************#
            self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

    #*************************************************************************#
    #* Setup before each test case (= each method below whose name begins    *#
    #* with "test").                                                         *#
    #*************************************************************************#
    def setUp(self):

        #*********************************************************************#
        #* Setup to control 0MQ socket operations.                           *#
        #*********************************************************************#
        self.setUp_sockets()

        #*********************************************************************#
        #* Setup to control logging.                                         *#
        #*********************************************************************#
        self.setUp_logging()

        #*********************************************************************#
        #* Setup to control the passage of time.                             *#
        #*********************************************************************#
        self.setUp_time()

        #*********************************************************************#
        #* Create an instance of CalicoMechanismDriver.                      *#
        #*********************************************************************#
        self.driver = mech_calico.CalicoMechanismDriver()

    def tearDown(self):
        pass

    def test_mainline(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Check that there's a socket bound to port 9901, and get it.       *#
        #*********************************************************************#
        bound_sockets = {socket for socket in self.sockets
                         if socket.bound_address == "tcp://*:9901"}
        self.assertEqual(len(bound_sockets), 1)
        self.felix_router_socket = bound_sockets.pop()
        print "Felix router socket is %s" % self.felix_router_socket

        #*********************************************************************#
        #* Check that there's a socket bound to port 9903, and get it.       *#
        #*********************************************************************#
        bound_sockets = {socket for socket in self.sockets
                         if socket.bound_address == "tcp://*:9903"}
        self.assertEqual(len(bound_sockets), 1)
        self.acl_get_socket = bound_sockets.pop()
        print "ACL GET socket is %s" % self.acl_get_socket

        #*********************************************************************#
        #* Check that there's a socket bound to port 9904, and get it.       *#
        #*********************************************************************#
        bound_sockets = {socket for socket in self.sockets
                         if socket.bound_address == "tcp://*:9904"}
        self.assertEqual(len(bound_sockets), 1)
        self.acl_pub_socket = bound_sockets.pop()
        print "ACL PUB socket is %s" % self.acl_pub_socket

        #*********************************************************************#
        #* Hook the Neutron database.                                        *#
        #*********************************************************************#
        self.db = mech_calico.manager.NeutronManager.get_plugin()
        self.db_context = mech_calico.ctx.get_admin_context()
        self.db.get_ports.return_value = []

        #*********************************************************************#
        #* Send a RESYNCSTATE.                                               *#
        #*********************************************************************#
        resync = {'type': 'RESYNCSTATE',
                  'resync_id': 'resync#1',
                  'issued': time.time() * 1000,
                  'hostname': 'felix-host-1'}
        self.felix_router_socket.rcv_queue.put_nowait(
            ['felix-1',
             '',
             json.dumps(resync).encode('utf-8')])
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        #*********************************************************************#
        #* Check DB got create_or_update_agent call.                         *#
        #*********************************************************************#
        self.db.create_or_update_agent.assert_called_once_with(
            self.db_context,
            {'agent_type': mech_calico.AGENT_TYPE_FELIX,
             'binary': '',
             'host': 'felix-host-1',
             'topic': mech_calico.constants.L2_AGENT_TOPIC,
             'start_flag': True})

        #*********************************************************************#
        #* Check RESYNCSTATE response was sent.                              *#
        #*********************************************************************#
        self.felix_router_socket.send_multipart.assert_called_once_with(
            ['felix-1',
             '',
             json.dumps({'type': 'RESYNCSTATE',
                         'endpoint_count': 0,
                         'rc': 'SUCCESS',
                         'message': 'Здра́вствуйте!'}).encode('utf-8')])
        self.felix_router_socket.send_multipart.reset_mock()

        #*********************************************************************#
        #* Send HEARTBEAT from Felix and check for response.                 *#
        #*********************************************************************#
        self.felix_router_socket.rcv_queue.put_nowait(
            ['felix-1',
             '',
             json.dumps({'type': 'HEARTBEAT'}).encode('utf-8')])
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
        self.felix_router_socket.send_multipart.assert_called_once_with(
            ['felix-1',
             '',
             json.dumps({'type': 'HEARTBEAT'}).encode('utf-8')])
        self.felix_router_socket.send_multipart.reset_mock()

        #*********************************************************************#
        #* Get the socket that the plugin used to connect back to Felix.     *#
        #*********************************************************************#
        connected_sockets = {socket for socket in self.sockets
                             if socket.connected_address == "tcp://felix-host-1:9902"}
        self.assertEqual(len(connected_sockets), 1)
        self.felix_endpoint_socket = connected_sockets.pop()
        print "Felix endpoint socket is %s" % self.felix_endpoint_socket

        #*********************************************************************#
        #* Need another yield here, apparently, to allow                     *#
        #* felix_heartbeat_thread to start running.                          *#
        #*********************************************************************#
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        #*********************************************************************#
        #* Receive HEARTBEAT to Felix from the plugin, and send response.    *#
        #*********************************************************************#
        self.simulated_time_advance(30)
        self.felix_endpoint_socket.send_json.assert_called_once_with(
            {'type': 'HEARTBEAT'},
            mech_calico.zmq.NOBLOCK)
        self.felix_endpoint_socket.send_json.reset_mock()
        self.felix_endpoint_socket.rcv_queue.put_nowait(
            {'type': 'HEARTBEAT'})
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        #*********************************************************************#
        #* Yield to allow anything pending on other threads to come out.     *#
        #*********************************************************************#
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

        #*********************************************************************#
        #* ACL Manager connection.                                           *#
        #*                                                                   *#
        #* - sim-ACLM: Connect to PLUGIN_ACLPUB_PORT, make normal            *#
        #*  subscriptions, wait a bit to ensure that Plugin's 0MQ layer has  *#
        #*  processed these.                                                 *#
        #*                                                                   *#
        #* - sim-DB: Prep response to next get_security_groups query,        *#
        #*  returning the default SG.  Prep null response to next            *#
        #*  _get_port_security_group_bindings call.                          *#
        #*                                                                   *#
        #* - sim-ACLM: Connect to PLUGIN_ACLGET_PORT, send GETGROUPS, check  *#
        #*  get GETGROUPS response.  Check get GROUPUPDATE publication       *#
        #*  describing default SG.                                           *#
        #*                                                                   *#
        #* - sim-ACLM: Send HEARTBEAT, check get HEARTBEAT response.         *#
        #*                                                                   *#
        #* - sim-ACLM: Wait for HEARTBEAT_SEND_INTERVAL_SECS, check get      *#
        #*   HEARTBEAT, send HEARTBEAT response.                             *#
        #*********************************************************************#

        #*********************************************************************#
        #* Mechanism driver entry points that are currently implemented as   *#
        #* no-ops (because Calico function does not need them).              *#
        #*                                                                   *#
        #* - sim-ML2: Call update_subnet_postcommit,                         *#
        #*   update_network_postcommit, delete_subnet_postcommit,            *#
        #*   delete_network_postcommit, create_network_postcommit,           *#
        #*   create_subnet_postcommit, update_network_postcommit,            *#
        #*   update_subnet_postcommit.                                       *#
        #*********************************************************************#

        #*********************************************************************#
        #* New endpoint processing.                                          *#
        #*                                                                   *#
        #* - sim-ML2: Call check_segment_for_agent with params so that it    *#
        #*   should return True.  Check get True.                            *#
        #*                                                                   *#
        #* - sim-DB: Prep response to next get_subnet call.                  *#
        #*                                                                   *#
        #* - sim-ML2: Call create_port_postcommit for an endpoint port with  *#
        #*   host_id matching sim-Felix.                                     *#
        #*                                                                   *#
        #* - sim-Felix: Check get ENDPOINTCREATED.  Send successful          *#
        #*   response.                                                       *#
        #*                                                                   *#
        #* - sim-DB: Check get update_port_status call, indicating port      *#
        #*   active.                                                         *#
        #*                                                                   *#
        #* - sim-DB: Prep appropriate responses for next get_security_group, *#
        #*   _get_port_security_group_bindings and get_port calls.           *#
        #*                                                                   *#
        #* - sim-ML2: Call security_groups_member_updated with default SG    *#
        #*   ID.                                                             *#
        #*                                                                   *#
        #* - sim-ACLM: Check get GROUPUPDATE publication indicating port     *#
        #*   added to default SG ID.                                         *#
        #*********************************************************************#

        #*********************************************************************#
        #* Endpoint update processing.                                       *#
        #*                                                                   *#
        #* - sim-DB: Prep response to next get_subnet call.                  *#
        #*                                                                   *#
        #* - sim-ML2: Call update_port_postcommit for an endpoint port with  *#
        #*   host_id matching sim-Felix.                                     *#
        #*                                                                   *#
        #* - sim-Felix: Check get ENDPOINTUPDATED.  Send successful          *#
        #*   response.                                                       *#
        #*********************************************************************#

        #*********************************************************************#
        #* SG rules update processing.                                       *#
        #*                                                                   *#
        #* - sim-DB: Prep appropriate responses for next get_security_group, *#
        #*   _get_port_security_group_bindings and get_port calls.           *#
        #*                                                                   *#
        #* - sim-ML2: Call security_groups_rule_updated with default SG ID.  *#
        #*                                                                   *#
        #* - sim-ACLM: Check get GROUPUPDATE publication indicating updated  *#
        #*   rules.                                                          *#
        #*********************************************************************#

        #*********************************************************************#
        #* Endpoint deletion processing.                                     *#
        #*                                                                   *#
        #* - sim-ML2: Call delete_port_postcommit for an endpoint port with  *#
        #*   host_id matching sim-Felix.                                     *#
        #*                                                                   *#
        #* - sim-Felix: Check get ENDPOINTDESTROYED.  Send successful        *#
        #*   response.                                                       *#
        #*                                                                   *#
        #* - sim-DB: Prep appropriate responses for next get_security_group, *#
        #*   _get_port_security_group_bindings and get_port calls.           *#
        #*                                                                   *#
        #* - sim-ML2: Call security_groups_member_updated with default SG    *#
        #*   ID.                                                             *#
        #*                                                                   *#
        #* - sim-ACLM: Check get GROUPUPDATE publication indicating port     *#
        #*   removed from default SG ID.                                     *#
        #*********************************************************************#

    def test_timing_new_endpoint(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Repeat mainline test with variation: for a new endpoint, sim-ML2  *#
        #* calls security_groups_member_updated before                       *#
        #* create_port_postcommit, instead of after it.                      *#
        #*********************************************************************#

    def test_timing_endpoint_deletion(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Repeat mainline test with variation: for an endpoint being        *#
        #* deleted, sim-ML2 calls security_groups_member_updated before      *#
        #* delete_port_postcommit, instead of after it.                      *#
        #*********************************************************************#

    def test_multiple_2(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Connect two Felix instances.  Create multiple endpoints, with     *#
        #* host-id selecting one of the available Felices.                   *#
        #*                                                                   *#
        #* Check plugin sends HEARTBEATs to both instances and correctly     *#
        #* processes HEARTBEATs from both instances.                         *#
        #*                                                                   *#
        #* Create lots of endpoints, spread across the two instances.  Then  *#
        #* get both instances to send RESYNCSTATE at the same time.          *#
        #*********************************************************************#

    def test_multiple_10(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Connect 10 Felix instances.  Create 100 endpoints, 10 for each    *#
        #* instance.  Put each endpoint into one of 10 SGs, so that each     *#
        #* Felix has one endpoint in each of the 10 SGs.  Get all 10         *#
        #* instances to send RESYNCSTATE in series (without any delay        *#
        #* between them).  Send GETGROUPS from ACL manager, check that all   *#
        #* SGs are correctly resent to ACL manager.                          *#
        #*********************************************************************#

    #*************************************************************************#
    #* Tests of partners disconnecting and/or connectivity trouble...        *#
    #*                                                                       *#
    #* Test the following possible errors to various socket                  *#
    #* operations. These all represent different manifestations of           *#
    #* networking connectivity trouble.                                      *#
    #*************************************************************************#
 
    def test_felix_router_addr_in_use(self):

        #*********************************************************************#
        #* Operations on the PLUGIN_ENDPOINT_PORT ROUTER socket.             *#
        #*                                                                   *#
        #* : self.felix_router_socket = self.zmq_context.socket(zmq.ROUTER)  *#
        #*                                                                   *#
        #* - 'Address in use' error when binding to PLUGIN_ENDPOINT_PORT.    *#
        #*********************************************************************#
        pass

    def test_acl_get_addr_in_use(self):

        #*********************************************************************#
        #* Operations on the PLUGIN_ACLGET_PORT ROUTER socket.               *#
        #*                                                                   *#
        #* : self.acl_get_socket = self.zmq_context.socket(zmq.ROUTER)       *#
        #*                                                                   *#
        #* - 'Address in use' error when binding to PLUGIN_ACLGET_PORT.      *#
        #*********************************************************************#
        pass

    def test_acl_pub_addr_in_use(self):

        #*********************************************************************#
        #* Operations on the PLUGIN_ACLPUB_PORT PUB socket.                  *#
        #*                                                                   *#
        #* : self.acl_pub_socket = self.zmq_context.socket(zmq.PUB)          *#
        #*                                                                   *#
        #* - 'Address in use' error when binding to PLUGIN_ACLPUB_PORT.      *#
        #*********************************************************************#
        pass

    def test_felix_eagain_snd_endpoint(self):

        #*********************************************************************#
        #* Operations on the FELIX_ENDPOINT_PORT REQ socket.                 *#
        #*                                                                   *#
        #* : sock = self.zmq_context.socket(zmq.REQ) :                       *#
        #* sock.setsockopt(zmq.LINGER, 0) : sock.connect("tcp://%s:%s" %     *#
        #* (hostname, FELIX_ENDPOINT_PORT)) :                                *#
        #* self.felix_peer_sockets[hostname] = sock                          *#
        #*                                                                   *#
        #* - 'EWOULDBLOCK' error when sending ENDPOINT* request.             *#
        #*********************************************************************#
        pass

    def test_felix_eagain_rcv_endpoint(self):

        #*********************************************************************#
        #* - 'EWOULDBLOCK' error when receiving ENDPOINT* response.          *#
        #*********************************************************************#
        pass

    def test_felix_eagain_snd_heartbeat(self):

        #*********************************************************************#
        #* - 'EWOULDBLOCK' error when sending HEARTBEAT request.             *#
        #*********************************************************************#
        pass

    def test_felix_eagain_rcv_heartbeat(self):

        #*********************************************************************#
        #* - 'EWOULDBLOCK' error when receiving HEARTBEAT response.          *#
        #*********************************************************************#
        pass

    def test_connectivity_blips(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Test the following scenarios, to check that plugin processing is  *#
        #* continuous and correct across connectivity blips.                 *#
        #*                                                                   *#
        #* - Connect a Felix, and process a new endpoint for that Felix.     *#
        #*   Simulate disconnection and reconnection, in the form of a       *#
        #*   RESYNCSTATE on new connection but with same hostname.  Check    *#
        #*   that the existing endpoint is sent on the new connection.       *#
        #*   Check that heartbeats occur as normal on the new connection.    *#
        #*                                                                   *#
        #* - Add another new endpoint for same hostname, and check it is     *#
        #*   processed normally and notified on the new connection.          *#
        #*                                                                   *#
        #* - Simulate disconnect and reconnect again, and check that both    *#
        #*   existing endpoints are notified on the new active connection    *#
        #*   (#3), after the new RESYNCSTATE.                                *#
        #*********************************************************************#

    def test_no_felix_new_endpoint(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* ** Error cases                                                    *#
        #*                                                                   *#
        #* Do new endpoint processing when required Felix is not available.  *#
        #* Check that sim-ML2 sees a FelixUnavailable exception from its     *#
        #* create_port_postcommit call.                                      *#
        #*                                                                   *#
        #* Call create_port_postcommit again with host-id changed to match a *#
        #* Felix that _is_ available.  Check that new endpoint processing    *#
        #* then proceeds normally.                                           *#
        #*********************************************************************#

    def test_no_felix_endpoint_update(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Do endpoint update processing when required Felix is not          *#
        #* available.  Check that sim-ML2 sees a FelixUnavailable exception  *#
        #* from its update_port_postcommit call.                             *#
        #*********************************************************************#

    def test_no_felix_endpoint_deleted(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* Do endpoint deletion processing when required Felix is not        *#
        #* available.  Check that sim-ML2 sees a FelixUnavailable exception  *#
        #* from its delete_port_postcommit call.                             *#
        #*********************************************************************#

    def test_code_coverage(self):

        #*********************************************************************#
        #* Tell the driver to initialize.                                    *#
        #*********************************************************************#
        self.driver.initialize()

        #*********************************************************************#
        #* ** Code coverage                                                  *#
        #*                                                                   *#
        #* After implementing and executing all of the above, review code    *#
        #* coverage and add further tests for any mech_calico.py lines that  *#
        #* have not yet been covered.  (Or else persuade ourselves that we   *#
        #* don't actually need those lines, and delete them.)                *#
        #*********************************************************************#
