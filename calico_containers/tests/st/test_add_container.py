from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestAddContainer(TestBase):
    def test_add_container(self):
        host = DockerHost('host')

        calicoctl = "/code/dist/calicoctl %s"

        host.execute("docker run -tid --name=node busybox")
        host.execute(calicoctl % "node --ip=127.0.0.1")
        host.execute(calicoctl % "profile add TEST_GROUP")

        self.assert_powerstrip_up(host)

        host.execute(calicoctl % "container add node 192.168.1.1")
        host.execute(calicoctl % "profile TEST_GROUP member add node")

        # Wait for felix to program down the route.
        powerstrip = partial(host.execute, "ip route | grep '192\.168\.1\.1'")
        assert self.retry_until_success(powerstrip, ex_class=ErrorReturnCode)
