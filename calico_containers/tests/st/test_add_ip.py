import unittest
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

        host.execute("docker run --net=calico:test -tid --name=node1 busybox")
        ip11 = host.execute("docker inspect --format "
                            "'{{ .NetworkSettings.IPAddress }}' "
                            "node1").stdout.rstrip()
        ip21 = "192.168.1.2"
        host.execute("docker run -tid --name=node2 busybox")
        host.calicoctl("container add node2 %s --interface=hello" % ip21)

        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        test_ping = partial(host.execute,
                            "docker exec node1 ping %s -c 1 -W 1" % ip21)
        retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Add two more addresses to node1 and one more to node2
        ip12 = "192.168.2.1"
        ip13 = "192.168.3.1"
        host.calicoctl("container node1 ip add %s" % ip12)
        host.calicoctl("container node1 ip add %s" % ip13)

        ip22 = "192.168.2.2"
        host.calicoctl("container node2 ip add %s --interface=hello" % ip22)

        host.execute("docker exec node1 ping %s -c 1" % ip22)
        host.execute("docker exec node2 ping %s -c 1" % ip11)
        host.execute("docker exec node2 ping %s -c 1" % ip12)
        host.execute("docker exec node2 ping %s -c 1" % ip13)

        # Now stop and restart node 1 and node 2.
        host.execute("docker stop node1")
        host.execute("docker stop node2")
        host.execute("docker start node1")
        host.execute("docker start node2")

        retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Test pings between the IPs.
        host.execute("docker exec node1 ping %s -c 1" % ip21)
        host.execute("docker exec node1 ping %s -c 1" % ip22)
        host.execute("docker exec node2 ping %s -c 1" % ip11)
        host.execute("docker exec node2 ping %s -c 1" % ip12)
        host.execute("docker exec node2 ping %s -c 1" % ip13)

        # Now remove and check pings to the removed addresses no longer work.
        host.calicoctl("container node1 ip remove %s" % ip12)
        host.calicoctl("container node2 ip remove %s "
                       "--interface=hello" % ip22)
        host.execute("docker exec node1 ping %s -c 1" % ip21)
        host.execute("docker exec node2 ping %s -c 1" % ip11)
        with self.assertRaises(ErrorReturnCode):
            host.execute("docker exec node1 ping %s -c 1 -W 1" % ip22)
        with self.assertRaises(ErrorReturnCode):
            host.execute("docker exec node2 ping %s -c 1 -W 1" % ip12)
        host.execute("docker exec node2 ping %s -c 1" % ip13)

        # Check that we can't remove addresses twice
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("container node1 ip remove %s" % ip12)
