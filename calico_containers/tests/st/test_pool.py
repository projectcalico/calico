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
import uuid

from tests.st.utils.constants import DEFAULT_IPV4_POOL_CIDR
from netaddr import IPNetwork
from test_base import TestBase
from tests.st.utils.docker_host import DockerHost

"""
Test calicoctl pool

1) Test the CRUD aspects of the pool commands.
2) Test IP assignment from pool.

BGP exported routes are hard to test and aren't expected to change much so
write tests for them (yet)

"""


class TestPool(TestBase):
    def test_pool_crud(self):
        """
        Test that a basic CRUD flow for pool commands.
        """
        with DockerHost('host', dind=False, start_calico=False) as host:

            # Set up the ipv4 and ipv6 pools to use
            ipv4_pool = "10.0.1.0/24"
            ipv6_pool = "fed0:8001::/64"

            # Run pool commands to add the ipv4 pool and show the pools
            host.calicoctl("pool add %s" % ipv4_pool)
            pool_out = host.calicoctl("pool show")

            # Assert output contains the ipv4 pool, but not the ipv6
            self.assertIn(ipv4_pool, pool_out)
            self.assertNotIn(ipv6_pool, pool_out)

            # Run pool commands to add the ipv6 pool and show the pools
            host.calicoctl("pool add %s" % ipv6_pool)
            pool_out = host.calicoctl("pool show")

            # Assert output contains both the ipv4 pool and the ipv6
            self.assertIn(ipv4_pool, pool_out)
            self.assertIn(ipv6_pool, pool_out)

            # Remove both the ipv4 pool and ipv6 pool
            host.calicoctl("pool remove %s" % ipv4_pool)
            host.calicoctl("pool remove %s" % ipv6_pool)
            pool_out = host.calicoctl("pool show")

            # Assert the pool show output does not contain either pool
            self.assertNotIn(ipv4_pool, pool_out)
            self.assertNotIn(ipv6_pool, pool_out)

    def test_pool_ip_assignment(self):
        """
        Test that pools can be used to control IP assignment.

        Remove default IPv4 pool.
        Add a new IPv4 pool.
        Create a new container.
        Assert container receives IP from new IPv4 pool.
        """
        with DockerHost('host', dind=False) as host:
            # Remove default pool and add new pool
            ipv4_pool = "10.0.1.0/24"
            host.calicoctl("pool remove %s" % DEFAULT_IPV4_POOL_CIDR)
            host.calicoctl("pool add %s" % ipv4_pool)

            # Setup network and add a container to the network
            network = host.create_network(str(uuid.uuid4()))
            workload = host.create_workload(str(uuid.uuid4()), network=network)

            # Assert the workload's ip came from the new IP pool
            self.assertIn(workload.ip, IPNetwork(ipv4_pool))

