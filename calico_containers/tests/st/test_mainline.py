from sh import docker, ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestMainline(TestBase):
    def run_mainline(self, ip1, ip2):
        """
        Setup two endpoints on one host and check connectivity.
        """
        host = DockerHost('host')
        host.start_etcd()

        host_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", host.name).stdout.rstrip()
        etcd_port = "ETCD_AUTHORITY=%s:2379" % host_ip
        calicoctl = etcd_port + " /code/dist/calicoctl %s"

        host.execute("docker run --rm  -v `pwd`:/target jpetazzo/nsenter", _ok_code=[0, 1])

        host.execute(calicoctl % "node --ip=127.0.0.1")
        host.execute(calicoctl % "profile add TEST_GROUP")

        # Wait for powerstrip to come up.
        self.assert_powerstrip_up(host)

        host.execute("docker run -e CALICO_IP=%s -tid --name=node1 busybox" % ip1, docker_host=True)
        host.execute("docker run -e CALICO_IP=%s -tid --name=node2 busybox" % ip2, docker_host=True)

        # Perform a docker inspect to extract the configured IP addresses.
        node1_ip = host.execute("docker inspect --format '{{ .NetworkSettings.IPAddress }}' node1",
                                docker_host=True).stdout.rstrip()
        node2_ip = host.execute("docker inspect --format '{{ .NetworkSettings.IPAddress }}' node2",
                                docker_host=True).stdout.rstrip()

        # Configure the nodes with the same profiles.
        host.listen(calicoctl % "profile TEST_GROUP member add node1")
        host.listen(calicoctl % "profile TEST_GROUP member add node2")

        node1_pid = host.execute("docker inspect --format {{.State.Pid}} node1").stdout.rstrip()
        node2_pid = host.execute("docker inspect --format {{.State.Pid}} node2").stdout.rstrip()

        ping = partial(host.listen, "./nsenter -t %s ping %s -c 1 -W 1" % (node1_pid, node2_ip))
        self.retry_until_success(ping, ex_class=ErrorReturnCode)

        # Check connectivity.
        host.execute("./nsenter -t %s ping %s -c 1" % (node1_pid, node1_ip))
        host.execute("./nsenter -t %s ping %s -c 1" % (node1_pid, node2_ip))
        host.execute("./nsenter -t %s ping %s -c 1" % (node2_pid, node1_ip))
        host.execute("./nsenter -t %s ping %s -c 1" % (node2_pid, node2_ip))

        # Test calicoctl teardown commands.
        host.execute(calicoctl % "profile remove TEST_GROUP")
        host.execute(calicoctl % "container remove node1")
        host.execute(calicoctl % "container remove node2")
        host.execute(calicoctl % "pool remove 192.168.0.0/16")
        host.execute(calicoctl % "node stop")

    def test_auto(self):
        """
        Run the test using auto assignment of IPs
        """
        self.run_mainline("auto", "auto")

    def test_hardcoded_ip(self):
        """
        Run the test using hard coded IPV4 assignments.
        """
        self.run_mainline("192.168.1.1", "192.168.1.2")
