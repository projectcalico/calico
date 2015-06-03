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
        host.assert_powerstrip_up()

        ip1, ip2 = "fd80:24e2:f998:72d6::1:1", "fd80:24e2:f998:72d6::1:2"
        node1 = host.create_workload("node1", ip=ip1, image="phusion/baseimage:0.9.16")
        node2 = host.create_workload("node2", ip=ip2, image="phusion/baseimage:0.9.16")

        # Configure the nodes with the same profiles.
        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node1)
        host.calicoctl("profile TEST_GROUP member add %s" % node2)

        ping = partial(node1.ping, ip2)
        retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        self.assert_connectivity([node1, node2])
