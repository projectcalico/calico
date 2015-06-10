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
        net_name = uuid.uuid4()
        with DockerHost('host', start_calico=False) as host:
            # TODO: Fix this for real
            host.ip6 = "fd80:1234:abcd::1"
            host.start_calico_node()
            host.assert_driver_up()

            # We use this image here because busybox doesn't have ping6.
            node1 = host.create_workload("node1", network=net_name,
                                         image="phusion/baseimage:0.9.16")
            node2 = host.create_workload("node2", network=net_name,
                                         image="phusion/baseimage:0.9.16")

            # Perform a docker inspect to extract the configured IP addresses.
            node1_ip = host.execute("docker inspect --format "
                                    "'{{ .NetworkSettings."
                                    "GlobalIPv6Address }}' "
                                    "node1").rstrip()
            node2_ip = host.execute("docker inspect --format "
                                    "'{{ .NetworkSettings."
                                    "GlobalIPv6Address }}' "
                                    "node2").rstrip()

            node1.assert_can_ping(node2.ip, retries=3)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

