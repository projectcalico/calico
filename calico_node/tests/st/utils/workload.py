# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import logging
from functools import partial

from netaddr import IPAddress

from exceptions import CommandExecError
from utils import retry_until_success, debug_failures

NET_NONE = "none"

logger = logging.getLogger(__name__)


class Workload(object):
    """
    A calico workload.

    These are the end-users containers that will run application-level
    software.
    """

    def __init__(self, host, name, image="busybox", network="bridge", ip=None, labels=[]):
        """
        Create the workload and detect its IPs.

        :param host: The host container on which this workload is instantiated.
        All commands executed by this container will be passed through the host
        via docker exec.
        :param name: The name given to the workload container. This name is
        passed to docker and can be used inside docker commands.
        :param image: The docker image to be used to instantiate this
        container. busybox used by default because it is extremely small and
        has ping.
        :param network: The DockerNetwork to connect to.  Set to None to use
        default Docker networking.
        :param ip: The ip address to assign to the container.
        :param labels: List of labels '<var>=<value>' to add to workload.
        """
        self.host = host
        self.name = name

        lbl_args = ""
        for label in labels:
            lbl_args += " --label %s" % (label)

        ip_option = ("--ip %s" % ip) if ip else ""
        command = "docker run -tid --name %s --net %s %s %s %s" % \
                  (name, network, lbl_args, ip_option, image)
        docker_run_wl = partial(host.execute, command)
        retry_until_success(docker_run_wl)
        self.ip = host.execute(
            "docker inspect --format "
            "'{{.NetworkSettings.Networks.%s.IPAddress}}' %s"
            % (network, name))

    def execute(self, command):
        """
        Execute arbitrary commands on this workload.
        """
        # Make sure we've been created in the context of a host. Done here
        # instead of in __init__ as we can't exist in the host until we're
        # created.
        assert self in self.host.workloads
        return self.host.execute("docker exec %s %s" % (self.name, command))

    def _get_ping_function(self, ip):
        """
        Return a function to ping the supplied IP address from this workload.

        :param ip: The IPAddress to ping.
        :return: A partial function that can be executed to perform the ping.
        The function raises a CommandExecError exception if the ping fails,
        or returns the output of the ping.
        """
        # Default to "ping"
        ping = "ping"

        try:
            version = IPAddress(ip).version
            assert version in [4, 6]
            if version == 6:
                ping = "ping6"
        except BaseException:
            pass

        args = [
            ping,
            "-c", "1",  # Number of pings
            "-W", "1",  # Timeout for each ping
            ip,
         ]
        command = ' '.join(args)

        ping = partial(self.execute, command)
        return ping

    @debug_failures
    def check_can_ping(self, ip, retries=0):
        """
        Execute a ping from this workload to the ip. Assert than a workload
        can ping an IP. Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently unreachable.

        :param ip:  The IP address (str or IPAddress) to ping.
        :param retries: The number of retries.
        :return: None.
        """
        try:
            retry_until_success(self._get_ping_function(ip),
                                retries=retries,
                                ex_class=CommandExecError)
        except CommandExecError:
            return False

        return True

    @debug_failures
    def check_cant_ping(self, ip, retries=0):
        """
        Execute a ping from this workload to the ip.  Assert that the workload
        cannot ping an IP.  Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently reachable.

        :param ip:  The IP address (str or IPAddress) to ping.
        :param retries: The number of retries.
        :return: None.
        """
        ping = self._get_ping_function(ip)

        def cant_ping():
            try:
                ping()
            except CommandExecError:
                pass
            else:
                raise _PingError()

        try:
            retry_until_success(cant_ping,
                                retries=retries,
                                ex_class=_PingError)
        except _PingError:
            return False

        return True

    def _get_tcp_function(self, ip):
        """
        Return a function to check tcp connectivity to another ip.

        :param ip: The ip to check against.
        :return: A partial function that can be executed to perform the check.
        The function raises a CommandExecError exception if the check fails,
        or returns the output of the check.
        """
        # test_string = "hello"
        args = [
            "/code/tcpping.sh",
            ip,
        ]

        command = ' '.join(args)

        tcp_check = partial(self.execute, command)
        return tcp_check

    def _get_tcp_asym_function(self, ip):
        """
        Return a function to check tcp connectivity to another ip.

        :param ip: The ip to check against.
        :return: A partial function that can be executed to perform the check.
        The function raises a CommandExecError exception if the check fails,
        or returns the output of the check.
        """
        # test_string = "hello"
        args = [
            "/code/tcppingasym.sh",
            ip,
        ]

        command = ' '.join(args)

        tcp_asym_check = partial(self.execute, command)
        return tcp_asym_check

    @debug_failures
    def check_can_tcp(self, ip, retries=0):
        """
        Execute a tcp check from this ip to the other ip.
        Assert that a ip can connect to another ip.
        Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently unreachable.

        :param ip:  The ip to check connectivity to.
        :param retries: The number of retries.
        :return: None.
        """
        try:
            retry_until_success(self._get_tcp_function(ip),
                                retries=retries,
                                ex_class=CommandExecError)
        except CommandExecError:
            return False

        return True

    @debug_failures
    def check_can_tcp_asym(self, ip, retries=0):
        """
        Execute a tcp check from this ip to the other ip.
        Assert that a ip can connect to another ip.
        Use retries to allow for convergence.
        Use of this method assumes the network will be transitioning from a
        state where the destination is currently unreachable.
        :param ip:  The ip to check connectivity to.
        :param retries: The number of retries.
        :return: None.
        """
        try:
            retry_until_success(self._get_tcp_asym_function(ip),
                                retries=retries,
                                ex_class=CommandExecError)
        except CommandExecError:
            return False

        return True

    @debug_failures
    def check_cant_tcp(self, ip, retries=0):
        """
        Execute a ping from this workload to an ip.
        Assert that the workload cannot connect to an IP using tcp.
        Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently reachable.

        :param ip:  The ip to check connectivity to.
        :param retries: The number of retries.
        :return: None.
        """
        tcp_check = self._get_tcp_function(ip)

        def cant_tcp():
            try:
                tcp_check()
            except CommandExecError:
                pass
            else:
                raise _PingError()

        try:
            retry_until_success(cant_tcp,
                                retries=retries,
                                ex_class=_PingError)
        except _PingError:
            return False

        return True

    def _get_udp_function(self, ip):
        """
        Return a function to check udp connectivity to another ip.

        :param ip: The ip to check against.
        :return: A partial function that can be executed to perform the check.
        The function raises a CommandExecError exception if the check fails,
        or returns the output of the check.
        """
        args = [
            "/code/udpping.sh",
            ip,
        ]

        command = ' '.join(args)

        udp_check = partial(self.execute, command)
        return udp_check

    @debug_failures
    def check_can_udp(self, ip, retries=0):
        """
        Execute a udp check from this workload to an ip.
        Assert that this workload can connect to another ip.
        Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently unreachable.

        :param ip:  The ip to check connectivity to.
        :param retries: The number of retries.
        :return: None.
        """
        try:
            retry_until_success(self._get_udp_function(ip),
                                retries=retries,
                                ex_class=CommandExecError)
        except CommandExecError:
            return False
        return True

    @debug_failures
    def check_cant_udp(self, ip, retries=0):
        """
        Execute a udp check from this workload to the ip.  Assert that
        the workload cannot connect via udp to an IP.
        Use retries to allow for convergence.

        Use of this method assumes the network will be transitioning from a
        state where the destination is currently reachable.

        :param ip:  The ip to check connectivity to.
        :param retries: The number of retries.
        :return: None.
        """
        udp_check = self._get_udp_function(ip)

        def cant_udp():
            try:
                udp_check()
            except CommandExecError:
                pass
            else:
                raise _PingError()

        try:
            retry_until_success(cant_udp,
                                retries=retries,
                                ex_class=_PingError)
        except _PingError:
            return False

        return True

    def __str__(self):
        return self.name


class _PingError(Exception):
    pass
