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
from subprocess import CalledProcessError
import uuid

from netaddr import IPAddress

from utils import retry_until_success
from calico_containers.tests.st.utils.network import DockerNetwork

NET_NONE = "none"

class Workload(object):
    """
    A calico workload.

    These are the end-users containers that will run application-level
    software.
    """
    def __init__(self, host, name, ip=None, image="busybox", network=None):
        """
        Create the workload and detect its IPs.

        :param host: The host container on which this workload is instantiated.
        All commands executed by this container will be passed through the host
        via docker exec.
        :param name: The name given to the workload container. This name is
        passed to docker and can be used inside docker commands.
        :param ip: The IP to be assigned to this workload via calico. May be
        either IPv4 or IPv6. May also be None or 'auto' in which case it will
        be assigned one by IPAM. Calico supports multiple IPs per workload, but
        this testing framework does not yet.
        :param image: The docker image to be used to instantiate this
        container. busybox used by default because it is extremely small and
        has ping.
        :param network: The DockerNetwork to connect to.  Set to None to use
        default Docker networking.
        """
        self.host = host
        self.name = name

        args = [
            "docker", "run",
            "--tty",
            "--interactive",
            "--detach",
            "--name", name,
        ]
        assert ip is None, "Static IP assignment not supported by libnetwork."
        if network:
            if network is not NET_NONE:
                assert isinstance(network, DockerNetwork)
            # We don't yet care about service names and they are buggy.
            # Currently they aren't deleted properly, so to ensure no
            # clashes between tests, just use a uuid
            args.append("--publish-service=%s.%s" % (str(uuid.uuid4()),
                                                     network))
        args.append(image)
        command = ' '.join(args)

        host.execute(command)

        # There is an unofficial ip=auto option in addition to ip=None.
        if ip is None:
            version = None
        else:
            version = IPAddress(ip).version

        if version == 6:
            version_key = "GlobalIPv6Address"
        else:
            version_key = "IPAddress"

        self.ip = host.execute("docker inspect --format "
                               "'{{ .NetworkSettings.%s }}' %s" % (version_key,
                                                                   name),
                               ).rstrip()

        if ip:
            # Currently unhittable until libnetwork lets us configure IPs.
            assert ip == self.ip, "IP param = %s, configured IP = %s." % \
                                  (ip, self.ip)

    def execute(self, command, **kwargs):
        """
        Execute arbitrary commands on this workload.
        """
        # Make sure we've been created in the context of a host. Done here
        # instead of in __init__ as we can't exist in the host until we're
        # created.
        assert self in self.host.workloads
        return self.host.execute("docker exec %s %s" % (self.name, command))

    def assert_can_ping(self, ip, retries=0):
        """
        Execute a ping from this workload to the ip. Assert than a workload
        can ping an IP. Use retries to compensate for network uncertainty and
        convergence.
        """
        version = IPAddress(ip).version
        assert version in [4, 6]
        if version == 4:
            ping = "ping"
        else:  # if version == 6:
            ping = "ping6"

        args = [
            ping,
            "-c", "1",  # Number of pings
            "-W", "1",  # Timeout for each ping
            ip,
        ]
        command = ' '.join(args)

        ping = partial(self.execute, command)
        return retry_until_success(ping,
                                   retries=retries,
                                   ex_class=CalledProcessError)

    def assert_cant_ping(self, ip, retries=0):
        for retry in range(retries + 1):
            self.assert_can_ping(ip)
            if retry >= retries:
                raise Exception("Workload can unexpectedly ping %s" % ip)

    def __str__(self):
        return self.name
