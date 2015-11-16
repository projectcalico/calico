# Copyright 2015 Metaswitch Networks
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
Usage:
  calicoctl ipam release <IP>
  calicoctl ipam info <IP>

Description:
  Manage Calico assigned IP addresses

Warnings:
  -  Releasing an in-use IP address can result in it being assigned to multiple
     workloads.
"""
import re
import sys

from etcd import EtcdKeyNotFound
from netaddr import IPAddress
from pycalico.block import AddressNotAssignedError
from pycalico.datastore import handle_errors
from pycalico.datastore import CONFIG_PATH, BGP_HOST_PATH, BGP_GLOBAL_PATH

from connectors import client
from utils import print_paragraph, validate_ip
from utils import hostname


def validate_arguments(arguments):
    """
    Validate argument values:
        <IP>

    :param arguments: Docopt processed arguments
    """
    # Validate IP
    container_ip_ok = arguments.get("<IP>") is None or \
                      validate_ip(arguments["<IP>"], 4) or \
                      validate_ip(arguments["<IP>"], 6)

    # Print error message and exit if not valid argument
    if not container_ip_ok:
        print "Invalid IP address specified."
        sys.exit(1)


def ipam(arguments):
    """
    Main dispatcher for ipam commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    if arguments.get("release"):
        release(arguments["<IP>"])
    elif arguments.get("info"):
        info(arguments["<IP>"])


def release(ip):
    """
    Release an IP address

    :param ip: The IP address (as a string).
    """
    address = IPAddress(ip)
    if client.release_ips({address}):
        print "Failed to release address"
    else:
        print "Address successfully released"


def info(ip):
    """
    Print the attributes defined for an IP address

    :param ip: The IP address (as a string).
    """
    address = IPAddress(ip)
    try:
        attributes = client.get_assignment_attributes(address)
        if attributes:
            print attributes
        else:
            print "No attributes defined for %s" % address
    except AddressNotAssignedError:
        print "IP %s is not currently assigned" % address
