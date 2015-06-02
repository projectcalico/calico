from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestIpv6(TestBase):
    def test_ipv6(self):
        """
        Test mainline functionality with IPv6 addresses.
        """
        host = DockerHost('host')

        host.execute("docker run --rm  -v `pwd`:/target jpetazzo/nsenter", _ok_code=[0, 1])

        calicoctl = "/code/dist/calicoctl %s"
        host.execute(calicoctl % ("node --ip=%s --ip6=%s" % (host.ip, host.ip6)))
        self.assert_powerstrip_up(host)

        ip1, ip2 = "fd80:24e2:f998:72d6::1:1", "fd80:24e2:f998:72d6::1:2"
        host.execute("docker run -e CALICO_IP=%s -tid --name=node1 phusion/baseimage:0.9.16" % ip1,
                     use_powerstrip=True)
        host.execute("docker run -e CALICO_IP=%s -tid --name=node2 phusion/baseimage:0.9.16" % ip2,
                     use_powerstrip=True)

        # Configure the nodes with the same profiles.
        host.execute(calicoctl % "profile add TEST_GROUP")
        host.execute(calicoctl % "profile TEST_GROUP member add node1")
        host.execute(calicoctl % "profile TEST_GROUP member add node2")

        # Perform a docker inspect to extract the configured IP addresses.
        node1_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.GlobalIPv6Address }}' node1",
                                use_powerstrip=True).stdout.rstrip()
        node2_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.GlobalIPv6Address }}' node2",
                                use_powerstrip=True).stdout.rstrip()

        self.assertEqual(ip1, node1_ip)
        self.assertEqual(ip2, node2_ip)

        node1_pid = host.execute("docker inspect --format '{{.State.Pid}}' node1").stdout.rstrip()
        node2_pid = host.execute("docker inspect --format '{{.State.Pid}}' node2").stdout.rstrip()

        ping = partial(host.execute, "./nsenter -t %s ping6 %s -c 1 -W 1" % (node1_pid, node2_ip))
        self.retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        host.execute("./nsenter -t %s ping6 %s -c 1" % (node1_pid, node1_ip))
        host.execute("./nsenter -t %s ping6 %s -c 1" % (node1_pid, node2_ip))
        host.execute("./nsenter -t %s ping6 %s -c 1" % (node2_pid, node1_ip))
        host.execute("./nsenter -t %s ping6 %s -c 1" % (node2_pid, node2_ip))
