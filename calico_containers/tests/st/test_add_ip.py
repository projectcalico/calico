import sh
from sh import docker, ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestAddIp(TestBase):
    def test_add_ip(self):
        host = DockerHost('host')
        host.start_etcd()

        calicoctl = "/code/dist/calicoctl %s"
        host.execute(calicoctl % "node --ip=172.17.8.10")
        host.execute(calicoctl % "profile add TEST_GROUP")

        self.assert_powerstrip_up(host)

        host.execute("docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox", docker_host=True)
        host.execute("docker run -tid --name=node2 busybox")
        host.execute(calicoctl % "container add node2 192.168.1.2 --interface=hello")

        host.execute(calicoctl % "profile TEST_GROUP member add node1")
        host.execute(calicoctl % "profile TEST_GROUP member add node2")

        test_ping = partial(host.execute, "docker exec node1 ping 192.168.1.2 -c 1 -W 1")
        assert self.retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Add two more addresses to node1 and one more to node2
        host.execute(calicoctl % "container node1 ip add 192.168.2.1")
        host.execute(calicoctl % "container node1 ip add 192.168.3.1")

        host.execute(calicoctl % "container node2 ip add 192.168.2.2 --interface=hello")

        host.execute("docker exec node1 ping 192.168.2.2 -c 1")
        host.execute("docker exec node2 ping 192.168.1.1 -c 1")
        host.execute("docker exec node2 ping 192.168.2.1 -c 1")
        host.execute("docker exec node2 ping 192.168.3.1 -c 1")

        # Now stop and restart node 1 and node 2.
        host.execute("sudo docker -H=localhost:2377 stop node1")
        host.execute("sudo docker -H=localhost:2377 stop node2")
        host.execute("sudo docker -H=localhost:2377 start node1")
        host.execute("sudo docker -H=localhost:2377 start node2")

        assert self.retry_until_success(test_ping, ex_class=ErrorReturnCode)

        # Test pings between the IPs.
        host.execute("docker exec node1 ping 192.168.1.2 -c 1")
        host.execute("docker exec node1 ping 192.168.2.2 -c 1")
        host.execute("docker exec node2 ping 192.168.1.1 -c 1")
        host.execute("docker exec node2 ping 192.168.2.1 -c 1")
        host.execute("docker exec node2 ping 192.168.3.1 -c 1")
        host.execute(calicoctl % "shownodes --detailed")

        # Now remove and check pings to the removed addresses no longer work.
        host.execute(calicoctl % "container node1 ip remove 192.168.2.1")
        host.execute(calicoctl % "container node2 ip remove 192.168.2.2 --interface=hello")
        host.execute("docker exec node1 ping 192.168.1.2 -c 1")
        host.execute("docker exec node2 ping 192.168.1.1 -c 1")
        with self.assertRaises(ErrorReturnCode):
            host.execute("docker exec node1 ping 192.168.2.2 -c 1 -W 1")
        with self.assertRaises(ErrorReturnCode):
            host.execute("docker exec node2 ping 192.168.2.1 -c 1 -W 1")
        host.execute("docker exec node2 ping 192.168.3.1 -c 1")
        host.execute(calicoctl % "shownodes --detailed")

        # Check that we can't remove addresses twice
        with self.assertRaises(ErrorReturnCode):
            host.execute(calicoctl % "container node1 ip remove 192.168.2.1")
