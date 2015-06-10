from subprocess import CalledProcessError
from functools import partial
import uuid

from test_base import TestBase
from docker_host import DockerHost


class TestIpv6(TestBase):
    def test_ipv6(self):
        """
        Test mainline functionality with IPv6 addresses.
        """
        # Use a UUID for net name so that independent runs of the test use
        # different names.  This helps in the case where etcd gets restarted
        # but Docker does not, since libnetwork will only create the network
        # if it doesn't exist.
        with DockerHost('host') as host:

            network = host.create_network(str(uuid.uuid4()))

            # We use this image here because busybox doesn't have ping6.
            node1 = host.create_workload("node1", network=network,
                                         image="phusion/baseimage:0.9.16")
            node2 = host.create_workload("node2", network=network,
                                         image="phusion/baseimage:0.9.16")

            # Allow network to converge
            node1.assert_can_ping(node2.ip, retries=3)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

