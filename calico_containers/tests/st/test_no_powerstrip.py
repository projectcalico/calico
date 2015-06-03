from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestNoPowerstrip(TestBase):
    def test_no_powerstrip(self):
        """
        Test mainline functionality without using powerstrip.
        """
        host = DockerHost('host')

        host.calicoctl("profile add TEST_GROUP")

        # Remove the environment variable such that docker run does not utilize
        # powerstrip.
        host.execute("docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox",
                     use_powerstrip=False)
        host.execute("docker run -e CALICO_IP=192.168.1.1 -tid --name=node2 busybox",
                     use_powerstrip=False)

        # Attempt to configure the nodes with the same profiles.  This will fail
        # since we didn't use powerstrip to create the nodes.
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("profile TEST_GROUP member add node1")
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("profile TEST_GROUP member add node2")

        # Add the nodes to Calico networking.
        host.calicoctl("container add node1 192.168.1.1")
        host.calicoctl("container add node2 192.168.1.2")

        # Now add the profiles.
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        # Inspect the nodes (ensure this works without powerstrip)
        host.execute("docker inspect node1")
        host.execute("docker inspect node2")

        # Check it works
        ping = partial(host.execute, "docker exec node1 ping 192.168.1.2 -c 1 -W 1")
        retry_until_success(ping, ex_class=ErrorReturnCode)

        host.execute("docker exec node1 ping 192.168.1.1 -c 1")
        host.execute("docker exec node1 ping 192.168.1.2 -c 1")
        host.execute("docker exec node2 ping 192.168.1.1 -c 1")
        host.execute("docker exec node2 ping 192.168.1.2 -c 1")

        # Test the teardown commands
        host.calicoctl("profile remove TEST_GROUP")
        host.calicoctl("container remove node1")
        host.calicoctl("container remove node2")
        host.calicoctl("pool remove 192.168.0.0/16")
        host.calicoctl("node stop")
