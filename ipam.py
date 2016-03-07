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

from docopt import docopt
from netaddr import IPNetwork

from pycalico.ipam import IPAMClient
from calico_cni import __version__, __commit__, __branch__
from calico_cni.util import (CniError, parse_cni_args,
                             configure_logging, print_cni_error)
from calico_cni.constants import *

__doc__ = """
Usage: calico-ipam [-vh]

Description:
    Calico CNI IPAM plugin.

Options:
    -h --help           Print this message.
    -v --version        Print the plugin version
"""

# Logging config.
LOG_FILENAME = "ipam.log"
_log = logging.getLogger("calico_cni")


class IpamPlugin(object):
    def __init__(self, environment, ipam_config):
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

        self.assign_ipv4 = ipam_config.get(ASSIGN_IPV4_KEY, "true") == "true"
        """
        Whether we should assign an IPv4 address - defaults to True.
        """

        self.assign_ipv6 = ipam_config.get(ASSIGN_IPV6_KEY, "false") == "true"
        """
        Whether we should assign an IPv6 address - defaults to False.
        """

        cni_args = parse_cni_args(environment.get(CNI_ARGS_ENV, ""))
        self.k8s_pod_name = cni_args.get(K8S_POD_NAME)
        self.k8s_namespace = cni_args.get(K8S_POD_NAMESPACE)
        """
        Only populated when running under Kubernetes.
        """

        # Validate the given environment and set fields.
        self._parse_environment(environment)

        if self.k8s_namespace and self.k8s_pod_name:
            self.workload_id = "%s.%s" % (self.k8s_namespace, self.k8s_pod_name)
        else:
            self.workload_id = self.container_id
        """
        Identifier for the workload.  In Kubernetes, this is the
        pod's namespace and name.  Otherwise, this is the container ID.
        """

    def execute(self):
        """
        Assigns or releases IP addresses for the specified workload.

        May raise CniError.

        :return: CNI ipam dictionary for ADD, None for DEL.
        """
        if self.command == "ADD":
            # Assign an IP address for this workload.
            _log.info("Assigning address to workload: %s", self.workload_id)
            ipv4, ipv6 = self._assign_address(handle_id=self.workload_id)

            # Build response dictionary.
            response = {}
            if ipv4:
                response["ip4"] = {"ip": str(ipv4.cidr)}
            if ipv6:
                response["ip6"] = {"ip": str(ipv6.cidr)}

            # Output the response and exit successfully.
            _log.debug("Returning response: %s", response)
            return json.dumps(response)
        else:
            # Release IPs using the workload_id as the handle.
            _log.info("Releasing addresses on workload: %s",
                      self.workload_id)
            try:
                self.datastore_client.release_ip_by_handle(
                        handle_id=self.workload_id
                )
            except KeyError:
                _log.warning("No IPs assigned to workload: %s",
                             self.workload_id)
                try:
                    # Try to release using the container ID.  Earlier
                    # versions of IPAM used the container ID alone
                    # as the handle. This allows us to be back-compatible.
                    _log.debug("Try release using container ID")
                    self.datastore_client.release_ip_by_handle(
                            handle_id=self.container_id
                    )
                except KeyError:
                    _log.debug("No IPs assigned to container: %s",
                               self.container_id)

    def _assign_address(self, handle_id):
        """
        Assigns an IPv4 and an IPv6 address.

        :return: A tuple of (IPv4, IPv6) address assigned.
        """
        ipv4 = None
        ipv6 = None

        # Determine which addresses to assign.
        num_v4 = 1 if self.assign_ipv4 else 0
        num_v6 = 1 if self.assign_ipv6 else 0
        _log.info("Assigning %s IPv4 and %s IPv6 addresses", num_v4, num_v6)
        try:
            ipv4_addrs, ipv6_addrs = self.datastore_client.auto_assign_ips(
                num_v4=num_v4, num_v6=num_v6, handle_id=handle_id,
                attributes=None,
            )
            _log.debug("Allocated ip4s: %s, ip6s: %s", ipv4_addrs, ipv6_addrs)
        except RuntimeError as e:
            _log.error("Cannot auto assign IPAddress: %s", e.message)
            raise CniError(ERR_CODE_GENERIC,
                           msg="Failed to assign IP address",
                           details=e.message)
        else:
            if num_v4:
                try:
                    ipv4 = IPNetwork(ipv4_addrs[0])
                except IndexError:
                    _log.error("No IPv4 address returned, exiting")
                    raise CniError(ERR_CODE_GENERIC,
                                   msg="No IPv4 addresses available in pool")

            if num_v6:
                try:
                    ipv6 = IPNetwork(ipv6_addrs[0])
                except IndexError:
                    _log.error("No IPv6 address returned, exiting")
                    raise CniError(ERR_CODE_GENERIC,
                                   msg="No IPv6 addresses available in pool")

            _log.info("Assigned IPv4: %s, IPv6: %s", ipv4, ipv6)
            return ipv4, ipv6

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
        output = IpamPlugin(env, config["ipam"]).execute()
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
    # Parse out the provided arguments.
    command_args = docopt(__doc__)

    # If the version argument was given, print version and exit.
    if command_args.get("--version"):
        print(json.dumps({"Version": __version__,
                          "Commit": __commit__,
                          "Branch": __branch__}, indent=2))
        sys.exit(0)

    main()
