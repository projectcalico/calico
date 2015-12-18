# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json
import os
import sys

from netaddr import IPNetwork

from pycalico.ipam import IPAMClient
from util import configure_logging, print_cni_error
from constants import *


# Logging config.
LOG_FILENAME = "ipam.log"
_log = logging.getLogger("calico_cni")

# Access to Calico Datastore.
datastore_client = IPAMClient()


class IpamPlugin(object):
    def __init__(self, config, environment):
        self.config = config
        """
        Dictionary representation of the config passed via stdin.
        """

        self.env = environment
        """
        Current environment (e.g os.environ)
        """

        self.command = None
        """
        Command indicating which action to take - one of "ADD" or "DEL".
        """

        self.container_id = None
        """
        Identifier for the container for which we are performing IPAM.
        """

        # Validate the given config and environment and set fields
        # using the given config and environment.
        self._parse_config()

    def execute(self):
        """
        Assigns or releases IP addresses for the specified container.
        :return:
        """
        if self.command == "ADD":
            # Assign an IP address for this container.
            _log.info("Assigning address to container %s", self.container_id)
            ipv4, ipv6 = self._assign_address(handle_id=self.container_id)
    
            # Output the response and exit successfully.
            print json.dumps({"ip4": {"ip": str(ipv4.cidr),},
                              "ip6": {"ip": str(ipv6.cidr),},})
        else:
            # Release any IP addresses for this container.
            assert self.command == CNI_CMD_DELETE, \
                    "Invalid command: %s" % self.command
    
            # Release IPs using the container_id as the handle.
            _log.info("Releasing address on container %s", 
                    self.container_id)
            try:
                datastore_client.release_ip_by_handle(handle_id=self.container_id)
            except KeyError:
                _log.warning("No IPs assigned to container_id %s", 
                        self.container_id)

    def _assign_address(self, handle_id, ipv4_pool=None, ipv6_pool=None):
        """
        Assigns an IPv4 and IPv6 address within the given pools.  
        If no pools are given, they will be automatically chosen.
    
        :return: A tuple of (IPv4, IPv6) address assigned.
        """
        ipv4 = IPNetwork("0.0.0.0") 
        ipv6 = IPNetwork("::") 
        pool = (ipv4_pool, ipv6_pool)
        try:
            ipv4_addrs, ipv6_addrs = datastore_client.auto_assign_ips(
                num_v4=1, num_v6=1, handle_id=handle_id, attributes=None,
                pool=pool
            )
            _log.debug("Allocated ip4s: %s, ip6s: %s", ipv4_addrs, ipv6_addrs)
        except RuntimeError as err:
            _log.error("Cannot auto assign IPAddress: %s", err.message)
            _exit_on_error(code=ERR_CODE_FAILED_ASSIGNMENT,
                           message="Failed to assign IP address",
                           details=err.message)
        else:
            try:
                ipv4 = ipv4_addrs[0]
            except IndexError:
                _log.error("No IPv4 address returned, exiting")
                _exit_on_error(code=ERR_CODE_FAILED_ASSIGNMENT,
                               message="No IPv4 addresses available in pool",
                               details = "")
            try:
                ipv6 = ipv6_addrs[0]
            except IndexError:
                _log.error("No IPv6 address returned, exiting")
                _exit_on_error(code=ERR_CODE_FAILED_ASSIGNMENT,
                               message="No IPv6 addresses available in pool",
                               details="")

            _log.info("Assigned IPv4: %s, IPv6: %s", ipv4, ipv6)
            return IPNetwork(ipv4), IPNetwork(ipv6)

    def _parse_config(self):
        """
        Validates that the plugins environment and given config contain 
        the required values.
        """
        _log.debug('Environment: %s', json.dumps(self.env, indent=2))
        _log.debug('Network config: %s', json.dumps(self.config, indent=2))
    
        # Check the given environment contains the required fields.
        try:
            self.command = env[CNI_COMMAND_ENV]
        except KeyError:
            _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                           message="Arguments Invalid",
                           details="CNI_COMMAND not found in environment")
        else:
            # If the command is present, make sure it is valid.
            if self.command not in [CNI_CMD_ADD, CNI_CMD_DELETE]:
                _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                               message="Arguments Invalid",
                               details="Invalid command '%s'" % self.command)

        try:
            self.container_id = env[CNI_CONTAINERID_ENV]
        except KeyError:
            _exit_on_error(code=ERR_CODE_INVALID_ARGUMENT,
                           message="Arguments Invalid",
                           details="CNI_CONTAINERID not found in environment")


def _exit_on_error(code, message, details=""):
    """
    Return failure information to the calling plugin as specified in the CNI spec and exit.
    :param code: Error code to return (int)
    :param message: Short error message to return.
    :param details: Detailed error message to return.
    :return:
    """
    print_cni_error(code, message, details)
    sys.exit(code)


if __name__ == '__main__':
    # Read config file from stdin.
    _log.debug("Reading config from stdin")
    conf_raw = ''.join(sys.stdin.readlines()).replace('\n', '')
    config = json.loads(conf_raw)

    # Get the log level from the config file, default to INFO.
    log_level = config.get(LOG_LEVEL_KEY, "INFO").upper()

    # Setup logger. We log to file and to stderr based on the 
    # log level provided in the network configuration file.
    configure_logging(_log, LOG_FILENAME, 
                      log_level=log_level, 
                      stderr_level=logging.INFO)

    # Get copy of environment.
    env = os.environ.copy()

    # Create plugin instance.
    plugin = IpamPlugin(config, env)

    try:
        # Execute IPAM.
        plugin.execute()
    except Exception, e:
        _log.exception("Unhandled exception")
        _exit_on_error(ERR_CODE_UNHANDLED,
              message="Unhandled Exception",
              details=e.message)
