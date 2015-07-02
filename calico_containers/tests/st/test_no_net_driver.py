from subprocess import CalledProcessError

from test_base import TestBase
from tests.st.utils.docker_host import DockerHost


class TestNoNetDriver(TestBase):
    def test_no_driver(self):
        """
        Test mainline functionality without using the docker network driver.
        """
        # TODO - work around https://github.com/docker/docker/issues/14107
        with DockerHost('host', dind=True) as host:
            host.calicoctl("profile add TEST_GROUP")

            # Use standard docker bridge networking.
            node1 = host.create_workload("node1")
            node2 = host.create_workload("node2")

            # Attempt to configure the nodes with the same profiles.  This will
            # fail since we didn't use the driver to create the nodes.
            with self.assertRaises(CalledProcessError):
                host.calicoctl("profile TEST_GROUP member add %s" % node1)
            with self.assertRaises(CalledProcessError):
                host.calicoctl("profile TEST_GROUP member add %s" % node2)

            # Add the nodes to Calico networking.
            host.calicoctl("container add %s 192.168.1.1" % node1)
            host.calicoctl("container add %s 192.168.1.2" % node2)

            # Get the endpoint IDs for the containers
            ep1 = host.calicoctl("container %s endpoint-id show" % node1)
            ep2 = host.calicoctl("container %s endpoint-id show" % node2)

            # Now add the profiles.
            host.calicoctl("endpoint %s profile set TEST_GROUP" % ep1)
            host.calicoctl("endpoint %s profile set TEST_GROUP" % ep2)

            # Check it works
            node1.assert_can_ping("192.168.1.2", retries=10)

            # Check reverse connectivity.
            node2.assert_can_ping("192.168.1.1")

            # Test the teardown commands
            host.calicoctl("profile remove TEST_GROUP")
            host.calicoctl("container remove %s" % node1)
            host.calicoctl("container remove %s" % node2)
            host.calicoctl("pool remove 192.168.0.0/16")
            host.calicoctl("node stop")
