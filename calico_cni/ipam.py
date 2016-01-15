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
from util import CniError


# Logging config.
LOG_FILENAME = "ipam.log"
_log = logging.getLogger("calico_cni")


class IpamPlugin(object):
    def __init__(self, environment):
        self.command = None
        """
        Command indicating which action to take - one of "ADD" or "DEL".
        """

        self.container_id = None
        """
        Identifier for the container for which we are performing IPAM.
        """

        self.datastore_client = IPAMClient()
        """
        Access to the datastore client.  Relies on ETCD_AUTHORITY environment
        variable being set by the calling plugin.
        """

        # Validate the given environment and set fields.
        self._parse_environment(environment)

    def execute(self):
        """
        Assigns or releases IP addresses for the specified container. 

        May raise CniError.
        
        :return: CNI ipam dictionary for ADD, None for DEL.
        """
        if self.command == "ADD":
            # Assign an IP address for this container.
            _log.info("Assigning address to container %s", self.container_id)
            ipv4, ipv6 = self._assign_address(handle_id=self.container_id)
    
            # Output the response and exit successfully.
            return json.dumps({"ip4": {"ip": str(ipv4.cidr)},
                               "ip6": {"ip": str(ipv6.cidr)}})
        else:
            # Release IPs using the container_id as the handle.
            _log.info("Releasing addresses on container %s", 
                      self.container_id)
            try:
                self.datastore_client.release_ip_by_handle(handle_id=self.container_id)
            except KeyError:
                _log.warning("No IPs assigned to container_id %s", 
                             self.container_id)

    def _assign_address(self, handle_id):
        """
        Assigns an IPv4 and an IPv6 address. 
    
        :return: A tuple of (IPv4, IPv6) address assigned.
        """
        ipv4 = IPNetwork("0.0.0.0") 
        ipv6 = IPNetwork("::") 
        try:
            ipv4_addrs, ipv6_addrs = self.datastore_client.auto_assign_ips(
                num_v4=1, num_v6=1, handle_id=handle_id, attributes=None,
            )
            _log.debug("Allocated ip4s: %s, ip6s: %s", ipv4_addrs, ipv6_addrs)
        except RuntimeError as e:
            _log.error("Cannot auto assign IPAddress: %s", e.message)
            raise CniError(ERR_CODE_GENERIC, 
                           msg="Failed to assign IP address",
                           details=e.message)
        else:
            try:
                ipv4 = ipv4_addrs[0]
            except IndexError:
                _log.error("No IPv4 address returned, exiting")
                raise CniError(ERR_CODE_GENERIC,
                               msg="No IPv4 addresses available in pool")
            try:
                ipv6 = ipv6_addrs[0]
            except IndexError:
                _log.error("No IPv6 address returned, exiting")
                raise CniError(ERR_CODE_GENERIC,
                               msg="No IPv6 addresses available in pool")

            _log.info("Assigned IPv4: %s, IPv6: %s", ipv4, ipv6)
            return IPNetwork(ipv4), IPNetwork(ipv6)

    def _parse_environment(self, env):
        """
        Validates the plugins environment and extracts the required values.
        """
        _log.debug('Environment: %s', json.dumps(env, indent=2))
    
        # Check the given environment contains the required fields.
        try:
            self.command = env[CNI_COMMAND_ENV]
        except KeyError:
            raise CniError(ERR_CODE_GENERIC,
                           msg="Invalid arguments",
                           details="CNI_COMMAND not found in environment")
        else:
            # If the command is present, make sure it is valid.
            if self.command not in [CNI_CMD_ADD, CNI_CMD_DELETE]:
                raise CniError(ERR_CODE_GENERIC,
                               msg="Invalid arguments",
                               details="Invalid command '%s'" % self.command)
        try:
            self.container_id = env[CNI_CONTAINERID_ENV]
        except KeyError:
            raise CniError(ERR_CODE_GENERIC,
                           msg="Invalid arguments",
                           details="CNI_CONTAINERID not found in environment")


def _exit_on_error(code, message, details=""):
    """
    Return failure information to the calling plugin as specified in the 
    CNI spec and exit.
    :param code: Error code to return (int)
    :param message: Short error message to return.
    :param details: Detailed error message to return.
    :return:
    """
    print_cni_error(code, message, details)
    sys.exit(code)


def main():
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

    try:
        # Execute IPAM.
        output = IpamPlugin(env).execute()
    except CniError as e:
        # We caught a CNI error - print the result to stdout and 
        # exit.
        _exit_on_error(e.code, e.msg, e.details)
    except Exception as e:
        _log.exception("Unhandled exception")
        _exit_on_error(ERR_CODE_GENERIC,
                       message="Unhandled Exception",
                       details=e.message)
    else:
        if output:
            print output


if __name__ == '__main__': # pragma: no cover
    main()
