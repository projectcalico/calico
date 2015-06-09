from subprocess import CalledProcessError
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestNoNetDriver(TestBase):
    def test_no_driver(self):
        """
        Test mainline functionality without using the docker network driver.
        """
        host = DockerHost('host')

        host.calicoctl("profile add TEST_GROUP")

        # Remove the environment variable such that docker run does not utilize
        # the docker network driver.
        host.execute("docker run -tid --name=node1 busybox")
        host.execute("docker run -tid --name=node2 busybox")

        # Attempt to configure the nodes with the same profiles.  This will
        # fail since we didn't use the driver to create the nodes.
        with self.assertRaises(CalledProcessError):
            host.calicoctl("profile TEST_GROUP member add node1")
        with self.assertRaises(CalledProcessError):
            host.calicoctl("profile TEST_GROUP member add node2")

        # Add the nodes to Calico networking.
        host.calicoctl("container add node1 192.168.1.1")
        host.calicoctl("container add node2 192.168.1.2")

        # Now add the profiles.
        host.calicoctl("profile TEST_GROUP member add node1")
        host.calicoctl("profile TEST_GROUP member add node2")

        # Inspect the nodes
        host.execute("docker inspect node1")
        host.execute("docker inspect node2")

        # Check it works
        ping = partial(host.execute,
                       "docker exec node1 ping 192.168.1.2 -c 1 -W 1")
        retry_until_success(ping, ex_class=CalledProcessError)

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
