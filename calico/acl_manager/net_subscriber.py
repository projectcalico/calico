# Copyright (c) 2014 Metaswitch Networks
# All Rights Reserved.
#
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

import logging
import zmq
from threading import Thread
import time
import json

log = logging.getLogger(__name__)

PLUGIN_ACLGET_PORT = "9903"
PLUGIN_ACLPUB_PORT = "9904"


class NetworkSubscriber(object):
    """
    Implements the Calico Network API.
    
    Responsible for learning network information (rules and security groups)
    from the Plugin, and passing it to a Network Store.  The Network Subscriber
    owns the ZeroMQ sockets that transport the Network API.
    """

    def __init__(self, context, network_store, plugin_address):
        """Create and start the Network Subscriber."""
        log.debug("Initializing Calico ACL Manager Network Subscriber")
        self.plugin_address = plugin_address
        self.subscribe_thread = Thread(target = self.subscribe_thread_func,
                                       args = (context, network_store))
        self.subscribe_thread.start()

    def subscribe_thread_func(self, context, network_store):
        """
        Create the sockets, perform start of day Network API synchronization 
        and then listen for published updates and pass them to the Network
        Store.
        """
        self.network_store = network_store
        
        # Create the SUB socket that receives updates to the network state.
        # Do this before start-of-day synchronization so that there's no window
        # during which the ACL Manager could miss updates.
        log.debug("Creating Network API subscriber socket")
        self.sub_socket = context.socket(zmq.SUB)
        self.sub_socket.connect("tcp://%(address)s:%(port)s" %
                                {"address": self.plugin_address,
                                 "port": PLUGIN_ACLPUB_PORT})
        self.sub_socket.setsockopt(zmq.SUBSCRIBE, "groups")
        self.sub_socket.setsockopt(zmq.SUBSCRIBE, "networkheartbeat")

        # Create the REQ socket used for start of day synchronization with the
        # plugin.
        log.debug("Creating Network API synchronization socket")
        self.req_socket = context.socket(zmq.REQ)
        self.req_socket.connect("tcp://%(address)s:%(port)s" %
                                {"address": self.plugin_address,
                                 "port": PLUGIN_ACLGET_PORT})

        # Perform the start of day synchronization.  Published updates are
        # queued during this, so none are lost.
        log.debug("Begin start of day synchronization")
        self.start_of_day_sync()
        log.debug("End start of day synchronization")

        # Listen for published updates to network state.
        log.debug("Begin listening for updates to network state")
        self.subscribe_loop()

    def start_of_day_sync(self):
        """Perform start of day synchronization over the Network API."""
        query = {"type": "GETGROUPS",
                 "issued": time.time() * 1000}
        self.req_socket.send_json(query)
        message = self.req_socket.recv()
        log.info("Received start of day response %s" % message)

    def subscribe_loop(self):
        """
        Listen for updates on the subscribe socket, parse them and pass them to
        the Netork Store.
        """
        while True:
            raw_message = self.sub_socket.recv_multipart()
            log.debug("Received message %s" % raw_message)
            subscription = raw_message[0].decode("utf-8")
            message = json.loads(raw_message[1].decode("utf-8"))
            log.info("Received published message %s" % message)
            if subscription == "networkheartbeat":
                assert message["type"] == "HEARTBEAT"
                log.info("Network API Heartbeat received")
            elif subscription == "groups":
                assert message["type"] == "GROUPUPDATE"
                log.info("Network API group update received")
                group_uuid = message["group"]
                members = message["members"]
                assert isinstance(members, dict)
                rules = message["rules"]
                self.network_store.update_group(group_uuid,
                                                members,
                                                rules)
            else:
                log.warning("Message received on unexpected subscription %s" %
                            subscription)