from subprocess import CalledProcessError
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        Test adding container to calico networking after it exists.
        """
        with DockerHost('host', dind=False) as host:
            # Create a container with --net=none, add a calico interface to
            # it then check felix programs a route.
            node = host.create_workload("node", network="none")

            host.calicoctl("container add %s 192.168.1.1" % node.name)

            # Add the container to a profile so felix will pick it up.
            host.calicoctl("profile add TEST_GROUP")
            host.calicoctl("profile TEST_GROUP member add %s" % node.name)

            # Wait for felix to program down the route.
            check_route = partial(host.execute,
                                  "ip route | grep '192\.168\.1\.1'")
            retry_until_success(check_route, ex_class=CalledProcessError)
