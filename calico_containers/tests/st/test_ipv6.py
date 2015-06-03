from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestIpv6(TestBase):
    def test_ipv6(self):
        """
        Test mainline functionality with IPv6 addresses.
        """
        host = DockerHost('host', start_calico=False)
        host.start_calico_node(ip=host.ip, ip6=host.ip6)
        host.assert_driver_up()

        host.execute("docker run --net=calico:test"
                     " -tid --name=node1 phusion/baseimage:0.9.16")
        host.execute("docker run --net=calico:test"
                     " -tid --name=node2 phusion/baseimage:0.9.16")

        # Configure the nodes with the same profiles.
        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        # Perform a docker inspect to extract the configured IP addresses.
        node1_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.GlobalIPv6Address }}' "
                                "node1").stdout.rstrip()
        node2_ip = host.execute("docker inspect --format "
                                "'{{ .NetworkSettings.GlobalIPv6Address }}' "
                                "node2").stdout.rstrip()

        ping = partial(host.execute,
                       "docker exec %s ping6 %s -c 1 -W 1" % ("node1",
                                                              node2_ip))
        retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        host.execute("docker exec %s ping6 %s -c 1" % ("node1", node1_ip))
        host.execute("docker exec %s ping6 %s -c 1" % ("node1", node2_ip))
        host.execute("docker exec %s ping6 %s -c 1" % ("node2", node1_ip))
        host.execute("docker exec %s ping6 %s -c 1" % ("node2", node2_ip))
