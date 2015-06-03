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

        host.execute("docker run -e CALICO_IP=%s -tid --name=node1 busybox" % ip1,
                     use_powerstrip=True)
        host.execute("docker run -e CALICO_IP=%s -tid --name=node2 busybox" % ip2,
                     use_powerstrip=True)

        # Configure the nodes with the same profiles.
        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        # Perform a docker inspect to extract the configured IP addresses.
        node1_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.IPAddress }}' node1",
                                use_powerstrip=True).stdout.rstrip()
        node2_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.IPAddress }}' node2",
                                use_powerstrip=True).stdout.rstrip()
        if ip1 != 'auto':
            self.assertEqual(ip1, node1_ip)
        if ip2 != 'auto':
            self.assertEqual(ip2, node2_ip)

        ping = partial(host.execute, "docker exec node1 ping %s -c 1 -W 1" % node1_ip)
        retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        host.execute("docker exec node1 ping %s -c 1" % node1_ip)
        host.execute("docker exec node1 ping %s -c 1" % node2_ip)
        host.execute("docker exec node2 ping %s -c 1" % node1_ip)
        host.execute("docker exec node2 ping %s -c 1" % node2_ip)

        # Test calicoctl teardown commands.
        host.calicoctl("profile remove TEST_GROUP")
        host.calicoctl("container remove node1")
        host.calicoctl("container remove node2")
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
