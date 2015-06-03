from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestAddIp(TestBase):
    def test_add_ip(self):
        """
        Test adding multiple IPs per workload.
        """
        host = DockerHost('host')

        node1 = host.create_workload("node1", "192.168.1.1")
        node2 = host.create_workload("node2")
        host.calicoctl("container add node2 192.168.1.2 --interface=hello")

        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        test_ping = partial(node1.ping, "192.168.1.2")
        retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Add two more addresses to node1 and one more to node2
        host.calicoctl("container node1 ip add 192.168.2.1")
        host.calicoctl("container node1 ip add 192.168.3.1")

        host.calicoctl("container node2 ip add 192.168.2.2 --interface=hello")

        node1.ping("192.168.2.2")
        node2.ping("192.168.1.1")
        node2.ping("192.168.2.1")
        node2.ping("192.168.3.1")

        # Now stop and restart node 1 and node 2.
        host.execute("docker stop node1", use_powerstrip=True)
        host.execute("docker stop node2", use_powerstrip=True)
        host.execute("docker start node1", use_powerstrip=True)
        host.execute("docker start node2", use_powerstrip=True)

        retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Test pings between the IPs.
        node1.ping("192.168.1.2")
        node1.ping("192.168.2.2")
        node2.ping("192.168.1.1")
        node2.ping("192.168.2.1")
        node2.ping("192.168.3.1")

        # Now remove and check pings to the removed addresses no longer work.
        host.calicoctl("container node1 ip remove 192.168.2.1")
        host.calicoctl("container node2 ip remove 192.168.2.2 --interface=hello")
        node1.ping("192.168.1.2")
        node2.ping("192.168.1.1")
        with self.assertRaises(ErrorReturnCode):
            node1.ping("192.168.2.2")
        with self.assertRaises(ErrorReturnCode):
            node2.ping("192.168.2.1")
        node2.ping("192.168.3.1")

        # Check that we can't remove addresses twice
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("container node1 ip remove 192.168.2.1")
