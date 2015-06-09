from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        Test adding container to calico networking after it exists.
        """
        host = DockerHost('host')

        node = host.create_workload("node")

        # Use the `container add` command instead of passing a CALICO_IP on
        # container creation. Note this no longer needs DOCKER_HOST specified.
        host.calicoctl("container add %s 192.168.1.1" % node.name)

        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node.name)

        # Wait for felix to program down the route.
        check_route = partial(host.execute, "ip route | grep '192\.168\.1\.1'")
        retry_until_success(check_route, ex_class=ErrorReturnCode)
