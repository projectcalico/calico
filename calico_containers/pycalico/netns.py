# Copyright (c) 2015 Metaswitch Networks
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

from subprocess32 import check_output, check_call
import socket
import logging
import logging.handlers
import os
import errno
import sys
import uuid

from netaddr import IPAddress

_log = logging.getLogger(__name__)

HOSTNAME = socket.gethostname()

PREFIX_LEN = {4: 32, 6: 128}
"""The IP address prefix length to assign, by IP version."""

IP_CMD_TIMEOUT = 5
"""How long to wait (seconds) for IP commands to complete."""


def setup_logging(logfile, level=logging.INFO):
    _log.setLevel(level)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    _log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    _log.addHandler(handler)


def create_veth(veth_name_host, veth_name_ns_temp):
    """
    Create the veth (pair).
    :param veth_name_host: The name of the veth interface
    :param veth_name_ns_temp: The temporary interface name of the veth that will be
    moved into the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    # Create the veth
    check_call(['ip', 'link',
                'add', veth_name_host,
                'type', 'veth',
                'peer', 'name', veth_name_ns_temp],
               timeout=IP_CMD_TIMEOUT)

    # Set the host end of the veth to 'up' so felix notices it.
    check_call(['ip', 'link', 'set', veth_name_host, 'up'],
               timeout=IP_CMD_TIMEOUT)


def remove_veth(veth_name_host):
    """
    Remove the veth (pair).
    :param interface_name: The name of the veth interface.
    :return: None. Raises CalledProcessError on error.
    """
    # The veth removal is best effort. If it fails then just log.
    check_call(['ip', 'link', 'del', veth_name_host], timeout=IP_CMD_TIMEOUT)


def move_veth_into_ns(cpid, veth_name_ns_temp, veth_name_ns):
    """
    Move the veth into the namespace.

    :param cpid: The PID of a process currently running in the namespace.
    :param veth_name_ns_temp: The temporary interface name of the veth that will be
    moved into the namespace.
    :param veth_name_ns: The name of the interface in the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    with NamedNamespace(cpid) as ns:
        # Create the veth pair and move one end into container:
        check_call(["ip", "link", "set", veth_name_ns_temp,
                    "netns", ns.name],
                   timeout=IP_CMD_TIMEOUT)
        ns.check_call(["ip", "link", "set", "dev", veth_name_ns_temp,
                       "name", veth_name_ns])
        ns.check_call(["ip", "link", "set", veth_name_ns, "up"])


def set_veth_mac(veth_name_host, mac):
    """
    Set the veth MAC address.
    :param veth_name_host: The name of the veth.
    :param mac: The MAC address.
    :return: None. Raises CalledProcessError on error.
    """
    #TODO MAC should be an EUI object.
    check_call(['ip', 'link', 'set',
                'dev', veth_name_host,
                'address', mac],
               timeout=IP_CMD_TIMEOUT)


def add_ns_default_route(cpid, next_hop, veth_name_ns):
    """
    Add a default route to the namespace.

    :param cpid: The PID of a process currently running in the namespace.
    :param next_hop: The next hop IP used as the default route in the namespace.
    :param veth_name_ns: The name of the interface in the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    assert isinstance(next_hop, IPAddress)
    with NamedNamespace(cpid) as ns:
        # Connected route to next hop & default route.
        ns.check_call(["ip", "-%s" % next_hop.version, "route", "replace",
                       str(next_hop), "dev", veth_name_ns])
        ns.check_call(["ip", "-%s" % next_hop.version, "route", "replace",
                      "default", "via", str(next_hop), "dev", veth_name_ns])


def get_ns_veth_mac(cpid, veth_name_ns):
    """
    Return the MAC address of the interface in the namespace.

    :param cpid: The PID of a process currently running in the namespace.
    :param veth_name_ns: The name of the interface in the namespace.
    :return: The MAC address as a string. Raises CalledProcessError on error.
    """
    with NamedNamespace(cpid) as ns:
        # Get the MAC address.
        mac = ns.check_output(["cat", "/sys/class/net/%s/address" % veth_name_ns]).strip()
    #TODO MAC should be an EUI object.
    return mac


def add_ip_to_ns_veth(container_pid, ip, veth_name_ns):
    """
    Add an IP to an interface in a namespace.

    :param container_pid: The PID of the namespace to operate in.
    :param ip: The IPAddress to add.
    :param veth_name_ns: The interface to add the address to.
    :return: None. Raises CalledProcessError on error.
    """
    with NamedNamespace(container_pid) as ns:
        ns.check_call(["ip", "-%s" % ip.version, "addr", "add",
                       "%s/%s" % (ip, PREFIX_LEN[ip.version]),
                       "dev", veth_name_ns])



def remove_ip_from_ns_veth(container_pid, ip, veth_name_ns):
    """
    Remove an IP from an interface in a namespace.

    :param container_pid: The PID of the namespace to operate in.
    :param ip: The IPAddress to remove.
    :param veth_name_ns: The interface to remove the address from.
    :return: None. raises CalledProcessError on error.
    """
    assert isinstance(ip, IPAddress)
    with NamedNamespace(container_pid) as ns:
        ns.check_call(["ip", "-%s" % ip.version, "addr", "del",
                       "%s/%s" % (ip, PREFIX_LEN[ip.version]),
                       "dev", "%(device)s" % veth_name_ns])


class NamedNamespace(object):
    """
    Create a named namespace from a PID namespace to allow us to run commands
    from within the namespace using standard `ip netns exec`.

    An alternative approach would be to use nsenter, which allows us to exec
    directly in a PID namespace.  However, this is not installed by default
    on some OSs that we need to support.
    """
    def __init__(self, cpid):
        self.name = uuid.uuid1().hex
        self.pid_dir = "/proc/%s/ns/net" % cpid
        self.nsn_dir = "/var/run/netns/%s" % self.name
        if not os.path.exists(self.pid_dir):
            raise NamespaceError("Namespace pseudofile %s does not exist." %
                                 self.pid_dir)

    def __enter__(self):
        """
        Add the appropriate configuration to name the namespace.  This links
        the PID to the namespace name.
        """
        _log.debug("Creating link between namespace %s and PID %s",
                   self.name, self.pid_dir)
        try:
            os.makedirs("/var/run/netns")
        except os.error as oserr:
            if oserr.errno != errno.EEXIST:
                _log.error("Unable to create /var/run/netns dir")
                raise
        os.symlink(self.pid_dir, self.nsn_dir)
        return self

    def __exit__(self, _type, _value, _traceback):
        try:
            os.unlink(self.nsn_dir)
        except BaseException:
            _log.exception("Failed to remove link: %s", self.nsn_dir)
        return False

    def check_call(self, command):
        """
        Run a command within the named namespace.
        :param command: The command to run.
        :param shell: Whether this is a shell command.
        :param timeout: Command timeout in seconds.
        """
        command = self._get_nets_command(command)
        _log.debug("Run command: %s", command)
        check_call(command, timeout=IP_CMD_TIMEOUT)

    def check_output(self, command):
        """
        Run a command within the named namespace.
        :param command: The command to run.
        :param shell: Whether this is a shell command.
        :param timeout: Command timeout in seconds.
        """
        command = self._get_nets_command(command)
        _log.debug("Run command: %s", command)
        return check_output(command, timeout=IP_CMD_TIMEOUT)

    def _get_nets_command(self, command):
        """
        Construct the netns command to execute.

        :param command: The command to execute.  This may either be a list or a
        single string.
        :return: The command to execute wrapped in the appropriate netns exec.
        If the original command was in list format, this returns a list,
        otherwise returns as a single string.
        """
        assert isinstance(command, list)
        return ["ip", "netns", "exec", self.name] + command


class NamespaceError(Exception):
    """
    Error creating or manipulating a network namespace.
    """
    pass
