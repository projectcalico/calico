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
from netaddr import IPAddress, AddrFormatError
from functools import partial
from sh import ErrorReturnCode_1

from utils import retry_until_success


class Workload(object):
    """
    A calico workload.

    These are the end-users containers that will run application-level software.
    """
    def __init__(self, host, name, ip=None, image="busybox", use_powerstrip=True):
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
        :param use_powerstrip: Use Powerstrip in front of docker to inform
        calico of networking changes.
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
        if ip:
            # Powerstrip passes the CALICO_IP var to calico.
            args += ["--env", "CALICO_IP=%s" % ip]
        args.append(image)
        command = ' '.join(args)

        # Capture the container_id returned by the start command
        results = host.execute(command, use_powerstrip=use_powerstrip)
        self.container_id = results.stdout.strip()

        # There is an unofficial ip=auto option in addition to ip=None.
        if ip is None or ip == 'auto':
            version = None
        else:
            version = IPAddress(ip).version

        # Because of a powerstrip limitation, we fail to pass the IPv6 address
        # to docker, so the GlobalIPv6Address field is blank.

        # if version == 6:
        #     version_key = "GlobalIPv6Address"
        # else:
        #     version_key = "IPAddress"

        # self.ip = host.execute("docker inspect --format "
        #                        "'{{ .NetworkSettings.%s }}' %s" % (version_key, name),
        #                        use_powerstrip=use_powerstrip).stdout.rstrip()
        # if ip and ip != 'auto':
        #     assert ip == self.ip, "IP param = %s, configured IP = %s." % (ip, self.ip)

        if version == 6:
            self.ip = ip
        else:
            self.ip = host.execute("docker inspect --format "
                                   "'{{ .NetworkSettings.IPAddress }}' %s" % name,
                                   use_powerstrip=use_powerstrip).stdout.rstrip()

        if version == 4:
            assert ip == self.ip, "IP param = %s, configured IP = %s." % (ip, self.ip)

    def execute(self, command, **kwargs):
        """
        Execute arbitrary commands on this workload.
        """
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
        elif version == 6:
            ping = "ping6"

        args = [
            ping,
            "-c", "1",  # Number of pings
            "-W", "1",  # Timeout for each ping
            ip,
        ]
        command = ' '.join(args)

        ping = partial(self.execute, command)
        return retry_until_success(ping, retries=retries, ex_class=ErrorReturnCode_1)

    def assert_cant_ping(self, ip, retries=0):
        for retry in range(retries + 1):
            try:
                self.assert_can_ping(ip)
            except ErrorReturnCode_1:
                return
            else:
                if retry >= retries:
                    raise Exception("Workload can unexpectedly ping %s" % ip)

    def __str__(self):
        return self.name
