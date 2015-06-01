from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        Test adding container to calico networking after it exists.
        """
        host = DockerHost('host')

        calicoctl = "/code/dist/calicoctl %s"

        host.execute("docker run -tid --name=node busybox")
        host.execute(calicoctl % "node --ip=127.0.0.1")
        host.execute(calicoctl % "profile add TEST_GROUP")

        self.assert_powerstrip_up(host)

        # Use the `container add` command instead of passing a CALICO_IP on
        # container creation. Note this no longer needs DOCKER_HOST specified.
        host.execute(calicoctl % "container add node 192.168.1.1")
        host.execute(calicoctl % "profile TEST_GROUP member add node")

        # Wait for felix to program down the route.
        check_route = partial(host.execute, "ip route | grep '192\.168\.1\.1'")
        assert self.retry_until_success(check_route, ex_class=ErrorReturnCode)
