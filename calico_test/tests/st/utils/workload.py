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
from functools import partial
import logging

from netaddr import IPAddress

from utils import retry_until_success, debug_failures
from network import DockerNetwork
from exceptions import CommandExecError
NET_NONE = "none"

logger = logging.getLogger(__name__)


class Workload(object):
    """
    A calico workload.

    These are the end-users containers that will run application-level
    software.
    """
    def __init__(self, host, name, image="busybox", network="bridge", ip=None):
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
        """
        self.host = host
        self.name = name

        ip_option = ("--ip %s" % ip) if ip else ""
        command = "docker run -tid --name %s --net %s %s %s" % \
                  (name, network, ip_option, image)
        host.execute(command)
        self.ip = host.execute("docker inspect --format "
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
    def assert_can_ping(self, ip, retries=0):
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
            raise AssertionError("%s cannot ping %s" % (self, ip))

    @debug_failures
    def assert_cant_ping(self, ip, retries=0):
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
            raise AssertionError("%s can ping %s" % (self, ip))

    def __str__(self):
        return self.name


class _PingError(Exception):
    pass
