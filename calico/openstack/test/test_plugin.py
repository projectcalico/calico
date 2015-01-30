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

Top level tests for the Calico/OpenStack Plugin.
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

    def setUp(self):

        #*********************************************************************#
        #* Set of addresses that we have sockets bound to.                   *#
        #*********************************************************************#
        self.sockets = set()

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
        #* Hook logging.                                                     *#
        #*********************************************************************#
        mech_calico.LOG = mock.Mock()
        mech_calico.LOG.info.side_effect = log_info
        mech_calico.LOG.debug.side_effect = log_debug
        mech_calico.LOG.warn.side_effect = log_warn
        mech_calico.LOG.exception.side_effect = log_exception

        #*********************************************************************#
        #* Create an instance of CalicoMechanismDriver.                      *#
        #*********************************************************************#
        self.driver = mech_calico.CalicoMechanismDriver()

        #*********************************************************************#
        #* Hook socket creation and binding.                                 *#
        #*********************************************************************#
        mech_calico.zmq.Context = mock.Mock()
        self.zmq_context = mech_calico.zmq.Context.return_value
        self.zmq_context.socket.side_effect = socket_created

        #*********************************************************************#
        #* Hook sleeping.                                                    *#
        #*********************************************************************#
        self.real_eventlet_sleep = eventlet.sleep
        mech_calico.eventlet.sleep = simulated_time_sleep

    #*************************************************************************#
    #* Advance the simulated time.                                           *#
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

    def tearDown(self):
        pass

    def test_startup(self):

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
