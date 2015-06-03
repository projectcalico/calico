from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestMainline(TestBase):
    def run_mainline(self, ip1, ip2):
        """
        Setup two endpoints on one host and check connectivity.
        """
        host = DockerHost('host')

        node1 = host.create_workload("node1", ip1)
        node2 = host.create_workload("node2", ip2)

        # Configure the nodes with the same profiles.
        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node1)
        host.calicoctl("profile TEST_GROUP member add %s" % node2)

        ping = partial(node1.ping, node1.ip)
        retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        self.assert_connectivity([node1, node2])

        # Test calicoctl teardown commands.
        host.calicoctl("profile remove TEST_GROUP")
        host.calicoctl("container remove %s" % node1)
        host.calicoctl("container remove %s" % node2)
        host.calicoctl("pool remove 192.168.0.0/16")
        host.calicoctl("node stop")

    def test_auto(self):
        """
        Run the test using auto assignment of IPs
        """
        self.run_mainline("auto", "auto")

    def test_hardcoded_ip(self):
        """
        Run the test using hard coded IPV4 assignments.
        """
        self.run_mainline("192.168.1.1", "192.168.1.2")
