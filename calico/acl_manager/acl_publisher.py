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
import time
from threading import Thread, Lock
import json

log = logging.getLogger(__name__)

MANAGER_ACLGET_PORT = "9905"
MANAGER_ACLPUB_PORT = "9906"


class ACLPublisher:
    """
    Implements the Calico ACL API.
    
    Responsible for transmitting ACL information from an ACL Store to Felixes.
    The ACL Publisher owns the ZeroMQ sockets that transport the API.
    """

    def __init__(self, context, acl_store):
        log.debug("Creating ACL Publisher")
        
        self.acl_store = acl_store
        
        # Create REP socket, used to receive ACL state requests from Felix.
        log.debug("Creating Publisher REP socket")
        self.router_socket = context.socket(zmq.ROUTER)
        self.router_socket.bind("tcp://*:%s" % MANAGER_ACLGET_PORT)

        # Create PUB socket, used to publish ACL updates to Felix.
        log.debug("Creating Publisher PUB socket")
        self.pub_socket = context.socket(zmq.PUB)
        self.pub_socket.bind("tcp://*:%s" % MANAGER_ACLPUB_PORT)
        
        # Create a lock to protect the PUB socket.
        self.pub_lock = Lock()
        
        # Start publish heartbeat worker thread.
        log.debug("Starting ACL heartbeat sending loop")
        self.heartbeat_thread = Thread(target = self.heartbeat_thread_func)
        self.heartbeat_thread.start()
        
        # Start query worker thread.
        log.debug("Starting Publisher query receive loop")
        self.query_thread = Thread(target = self.query_thread_func)
        self.query_thread.start()

    def publish_endpoint_acls(self, endpoint_uuid, acls):
        """Publish a set of ACL rules for an endpoint.
        
        This method is thread-safe.
        """
        log.info("Publishing ACL Update %s for %s" % (acls, endpoint_uuid))
        update = {"type": "ACLUPDATE",
                  "issued": time.time() * 1000,
                  "acls": acls}
        self.pub_lock.acquire()
        self.pub_socket.send_multipart([endpoint_uuid.encode("utf-8"),
                                        json.dumps(update).encode("utf-8")])
        self.pub_lock.release()
        
    def query_thread_func(self):
        """Query receive loop.
        
        Monitors the ROUTER socket for incoming queries and passes them on to 
        the ACL Store, which will asynchronously respond by calling back into
        publish_endpoint_acls() to send the update containing the ACL state.
        """
        while True:
            # Receive and parse the query message.
            message = self.router_socket.recv_multipart()
            assert (len(message) == 3)
            assert not message[1]
            query = json.loads(message[2].decode('utf-8'))
            peer = message[0]
            assert ("type" in query)
            log.info("ACL Manager received packet %s from %s", query, peer)

            if query["type"] == "GETACLSTATE":
                endpoint = query["endpoint_id"]
                log.info("Received query message %s from Felix" % message)
                self.acl_store.query_endpoint_rules(endpoint)
                query["rc"] = "SUCCESS"
                query["message"] = ""
            else:
                # Received unexpected message.  Log and return it.
                log.warning("Received query %s of unknown type" % query)
                query["rc"] = "FAILURE"
                query["message"] = "Unknown message type: expected GETACLSTATE"
            
            log.debug("Sending response message: %s, %s" %
                                     (peer, json.dumps(query).encode("utf-8")))
            self.router_socket.send_multipart(
                (peer,
                 "",
                 json.dumps(query).encode("utf-8"))
            )
            
    def heartbeat_thread_func(self):
        """ACL update socket heartbeat publishing loop.
        
        Sends a heartbeat to the aclheartbeat subscription on the PUB socket
        every 30 seconds.
        """
        while True:
            heartbeat = json.dumps({"type": "HEARTBEAT",
                                    "issued": time.time() * 1000})
            log.info("Sending ACL heartbeat %s" % heartbeat)
            self.pub_lock.acquire()
            self.pub_socket.send_multipart(["aclheartbeat",
                                            "",
                                            heartbeat.encode("utf-8")])
            self.pub_lock.release()
            log.debug("Sent ACL heartbeat")
            
            # In a perfect world this should subtract the time spent waiting
            # for the lock and sending the packet.  For the moment, in normal
            # operation this will suffice.
            time.sleep(30)