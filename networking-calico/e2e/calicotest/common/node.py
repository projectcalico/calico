# -*- coding: utf-8 -*-
# Copyright (c) 2014-2026 Tigera, Inc. All rights reserved.
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
calicotest.common.node
~~~~~~~~~~~~~~~

Contains the representation of virtual machines used throughout the
tests (e.g. for the Compute and Control nodes in an OpenStack cluster.

This module provides basic functionality to access a node to issue
CLI commands, send/retrieve files etc.
"""
import logging

from calicotest.common.ssh import SSH
from calicotest.common import osutils

_log = logging.getLogger(__name__)


class IpNotFound(Exception):
    pass


class Node(SSH):
    """
    A single node running on a host.  These nodes are themselves used as
    compute and control nodes in OpenStack etc., but the nodes really just
    represent a server running on a virtual host and can be used for anything.

    :param vmname: The node's section name in the cluster layout file; used in
    diags file names.
    :param fqdn: The FQDN of the machine.
    :param username: The username to use to access the host.
    :param password: The password to use to authenticate to the host.
    :param ip: The IP to use for this node in any configuration scripts that
    we generate; typically this means the IP that other nodes will use to
    connect to this one. If None, we get the IP to use by resolving the
    machine's FQDN.
    """

    def __init__(
        self,
        vmname,
        fqdn,
        username,
        password,
        keyfile=None,
        ip=None,
        region=None,
    ):
        self.vmname = vmname
        self._ip = ip
        self.region = region
        super(Node, self).__init__(fqdn, username, password, keyfile=keyfile)

    def __repr__(self):
        return "Node(%s,%s,%s)" % (self.fqdn, self.vmname, self.get_ipv4())

    def __str__(self):
        return self.__repr__()

    def execute(self, command):
        self.connect()
        return super(Node, self).execute(command)

    def get_pids(self, process):
        """
        Get the PIDs for the supplied process filter.  This is a grep
        regex that will uniquely identify the process from the output of
        ps.

        :param process: A grep regex.
        :return:  List of process IDs.
        """
        rc = self.execute("pgrep -f %s" % process)
        _log.debug("Lines from ps: %r", rc.stdout)
        pids = [int(s) for s in rc.stdout.splitlines()]
        _log.debug("PIDs: %r", pids)
        return pids

    def get_ipv4(self):
        """
        Returns a string containing the IPv4 of the node.  This is either the
        value of self.ip or looked up if self.ip is None.
        :return: a string containing the IP of the node.
        """
        if self._ip is None:
            return osutils.get_host_ip(self.fqdn, 4)
        return self._ip

    def get_if_name(self, ip):
        """
        Returns a string containing the name of the interface with the ip
        address specified.
        :param ip: the ip address we're looking for
        :return: a string containing the name of the interface (or raises an
        IpNotFound exception if the IP was not found)
        """
        # The output of: `ip -o -f inet a` looks like:
        # 1: lo    inet 127.0.0.1/8 scope host lo
        # 2: eth0    inet 192.168.15.7/24 brd 192.168.15.255 scope global eth0
        # 3: eth1    inet 192.168.16.5/24 brd 192.168.16.255 scope global eth1
        interface_dict = {}
        host_os = self.get_host_os()
        if "ubuntu" in host_os:
            _, stdout, _ = self.execute("/sbin/ip -o -f inet a")
        else:
            _log.error("Unable to recognise host's OS")
            raise IpNotFound
        for line in stdout.splitlines():
            if len(line.split()) > 3:
                cidr = line.split()[3]
                int_ip = cidr.split("/")[0]
                if_name = line.split()[1]
                interface_dict[int_ip] = if_name
        if ip not in interface_dict:
            _log.error("Could not find interface with ip %s", ip)
            raise IpNotFound
        else:
            return interface_dict[ip]

    @property
    def hostname(self):
        return self.fqdn.split(".")[0]

    def get_host_os(self):
        _, stdout, _ = self.execute('grep "^NAME=" /etc/os-release')
        return stdout.lower()
