import unittest
import uuid

from test_base import TestBase
from docker_host import DockerHost


class TestMainline(TestBase):
    def run_mainline(self, ip1, ip2):
        """
        Setup two endpoints on one host and check connectivity.
        """
        with DockerHost('host') as host:
            network = host.create_network(str(uuid.uuid4()))
            node1 = host.create_workload("node1", network=network)
            node2 = host.create_workload("node2", network=network)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

            # Test calicoctl teardown commands.
            host.execute("docker rm -f %s" % node1)
            host.execute("docker rm -f %s" % node2)
            host.calicoctl("pool remove 192.168.0.0/16")
            host.calicoctl("node stop")

    def test_auto(self):
        """
        Run the test using auto assignment of IPs
        """
        self.run_mainline("auto", "auto")

    @unittest.skip("Docker Driver doesn't support static IP assignment yet.")
    def test_hardcoded_ip(self):
        """
        Run the test using hard coded IPV4 assignments.
        """
        self.run_mainline("192.168.1.1", "192.168.1.2")
