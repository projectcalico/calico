from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestNoPowerstrip(TestBase):
    def test_no_powerstrip(self):

        host = DockerHost('host')

        calicoctl = "/code/dist/calicoctl %s"

        host.execute("docker run --rm  -v `pwd`:/target jpetazzo/nsenter", _ok_code=[0, 1])

        host.execute(calicoctl % "node --ip=127.0.0.1")
        host.execute(calicoctl % "profile add TEST_GROUP")

        self.assert_powerstrip_up(host)

        # Remove the environment variable such that docker run does not utilize
        # powerstrip.
        host.execute("docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox")
        host.execute("docker run -e CALICO_IP=192.168.1.1 -tid --name=node2 busybox")

        # Attempt to configure the nodes with the same profiles.  This will fail
        # since we didn't use powerstrip to create the nodes.
        with self.assertRaises(ErrorReturnCode):
            host.execute(calicoctl % "profile TEST_GROUP member add node1")
        with self.assertRaises(ErrorReturnCode):
            host.execute(calicoctl % "profile TEST_GROUP member add node2")

        # Add the nodes to Calico networking.
        host.execute(calicoctl % "container add node1 192.168.1.1")
        host.execute(calicoctl % "container add node2 192.168.1.2")

        # Now add the profiles.
        host.execute(calicoctl % "profile TEST_GROUP member add node1")
        host.execute(calicoctl % "profile TEST_GROUP member add node2")

        # Inspect the nodes (ensure this works without powerstrip)
        host.execute("docker inspect node1")
        host.execute("docker inspect node2")

        # Check it works
        ping = partial(host.execute, "docker exec node1 ping 192.168.1.2 -c 1 -W 1")
        self.retry_until_success(ping, ex_class=ErrorReturnCode)

        host.execute("docker exec node1 ping 192.168.1.1 -c 1")
        host.execute("docker exec node1 ping 192.168.1.2 -c 1")
        host.execute("docker exec node2 ping 192.168.1.1 -c 1")
        host.execute("docker exec node2 ping 192.168.1.2 -c 1")

        # Tear it down
        host.execute(calicoctl % "profile remove TEST_GROUP")
        host.execute(calicoctl % "container remove node1")
        host.execute(calicoctl % "container remove node2")
        host.execute(calicoctl % "pool remove 192.168.0.0/16")
        host.execute(calicoctl % "node stop")
