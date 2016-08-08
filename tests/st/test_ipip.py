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
from unittest import skip
import re
import subprocess

from netaddr import IPAddress, IPNetwork
from test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from time import sleep
from tests.st.utils.utils import retry_until_success

"""
Test calico IPIP behaviour

This needs to be a multihost test (so there is actually a cross-host tunnel).
TODO - how do we actually assert that traffic is encapsulated. Maybe packet
capture?
"""


class TestIPIP(TestBase):
    def tearDown(self):
        self.remove_tunl_ip()

    @skip("Not written yet")
    def test_ipip(self):
        pass

    def test_ipip_addr_assigned(self):
        with DockerHost('host', dind=False, start_calico=False) as host:
            # Set up first pool before Node is started, to ensure we get tunl IP on boot
            ipv4_pool = IPNetwork("10.0.1.0/24")
            host.calicoctl("pool add %s --ipip" % ipv4_pool)
            host.start_calico_node()
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Test that removing tunl removes the tunl IP.
            host.calicoctl("pool remove %s" % ipv4_pool)
            self.assert_tunl_ip(host, ipv4_pool, expect=False)

            # Test that re-adding the pool triggers the confd watch and we get an IP
            host.calicoctl("pool add %s --ipip" % ipv4_pool)
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Test that by adding another pool, then deleting the first,
            # we remove the original IP, and allocate a new one from the new pool
            new_ipv4_pool = IPNetwork("192.168.0.0/16")
            host.calicoctl("pool add %s --ipip" % new_ipv4_pool)
            host.calicoctl("pool remove %s" % ipv4_pool)
            self.assert_tunl_ip(host, new_ipv4_pool)


    def assert_tunl_ip(self, host, ip_network, expect=True):
        """
        Helper function to make assertions on whether or not the tunl interface
        on the Host has been assigned an IP or not. This function will retry
        7 times, ensuring that our 5 second confd watch will trigger.

        :param host: DockerHost object
        :param ip_network: IPNetwork object which describes the ip-range we do (or do not)
        expect to see an IP from on the tunl interface.
        :param expect: Whether or not we are expecting to see an IP from IPNetwork on the tunl interface.
        :return:
        """
        retries = 7
        for retry in range(retries + 1):
            try:
                output = host.execute("ip addr show tunl0")
                match = re.search(r'inet ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', output)
                if match:
                    ip_address = IPAddress(match.group(1))
                    if expect:
                        self.assertIn(ip_address, ip_network)
                    else:
                        self.assertNotIn(ip_address, ip_network)
                else:
                    self.assertFalse(expect, "No IP address assigned to tunl interface.")
            except Exception as e:
                if retry < retries:
                    sleep(1)
                else:
                    raise e
            else:
                return

    def remove_tunl_ip(self):
        """
        Remove tunl IP address if assigned.
        """
        try:
            output = subprocess.check_output(["ip", "addr", "show", "tunl0"])
        except subprocess.CalledProcessError:
            return

        match = re.search(r'inet ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', output)
        if not match:
            return

        ipnet = str(IPNetwork(match.group(1)))

        try:
            output = subprocess.check_output(["ip", "addr", "del", ipnet, "dev", "tunl0"])
        except subprocess.CalledProcessError:
            return
