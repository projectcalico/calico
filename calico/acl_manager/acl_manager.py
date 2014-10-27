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

import zmq
import logging
from net_subscriber import NetworkSubscriber
from net_store import NetworkStore
from acl_publisher import ACLPublisher
from acl_store import ACLStore
from processor import RuleProcessor

log = logging.getLogger(__name__)

def main():
    logging.basicConfig(filename="acl_manager.log", level=logging.DEBUG)
    
    # Create ZeroMQ context.
    context = zmq.Context()
    log.info("pyzmq version is %s" % zmq.pyzmq_version())
    
    # Create and start components.
    acl_store = ACLStore()
    network_store = NetworkStore()
    
    publisher = ACLPublisher(context, acl_store)
    acl_store.start(publisher)

    processor = RuleProcessor(acl_store, network_store)
    network_store.add_processor(processor)
    
    subscriber = NetworkSubscriber(context, network_store)

if __name__ == "__main__":
    main()