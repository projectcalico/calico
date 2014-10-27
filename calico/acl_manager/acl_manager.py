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
import argparse
import ConfigParser
import os
from calico.acl_manager.net_subscriber import NetworkSubscriber
from calico.acl_manager.net_store import NetworkStore
from calico.acl_manager.acl_publisher import ACLPublisher
from calico.acl_manager.acl_store import ACLStore
from calico.acl_manager.processor import RuleProcessor
from calico import common

log = logging.getLogger(__name__)

def main():
    # Parse command line args.
    parser = argparse.ArgumentParser(description='Calico ACL Manager')
    parser.add_argument('-c', '--config-file', dest='config_file')
    args = parser.parse_args()

    # Read config file.
    config = ConfigParser.ConfigParser()
    config.read(args.config_file or 'acl_manager.cfg')
    plugin_address = config.get('global', 'PluginAddress')
    log_file_path = config.get('log', 'LogFilePath')

    # Configure logging.
    common.mkdir_p(os.path.dirname(log_file_path))
    logging.basicConfig(filename=log_file_path, level=logging.DEBUG)
    
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
    
    subscriber = NetworkSubscriber(context, network_store, plugin_address)

if __name__ == "__main__":
    main()
