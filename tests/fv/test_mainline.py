import unittest
import sh
from sh import docker
from time import sleep


class TestMainline(unittest.TestCase):
    def run_mainline(self, ip1, ip2):
        """
        Setup two endpoints on one host and check connectivity.
        """
        docker_exec = docker.bake("exec")
        host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")
        host1_listen = docker_exec.bake("-i", "host1", "bash", "-s")

        host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host1").stdout.rstrip()
        etcd_port = "ETCD_AUTHORITY=%s:2379" % host1_ip
        calicoctl = etcd_port + " /code/dist/calicoctl %s"
        calico_port = "DOCKER_HOST=localhost:2377"

        print "cleanup"
        host1_exec("docker rm -f node1 node2 etcd", _ok_code=[0, 1])
        host1_exec("docker run --rm  -v `pwd`:/target jpetazzo/nsenter", _ok_code=[0, 1])
        host1_exec(calicoctl % "reset", _ok_code=[0, 1])

        print "Start calico node"
        host1_exec(calicoctl % "node --ip=127.0.0.1")
        host1_exec(calicoctl % "profile add TEST_GROUP")

        # Wait for powerstrip to come up.
        for i in range(3):
            try:
                host1_listen(_in="%s docker ps" % calico_port)
                break
            except sh.ErrorReturnCode:
                if i == 2:
                    raise AssertionError
                else:
                    sleep(1)

        print "Add endpoints"
        host1_listen(_in="%s docker run -e CALICO_IP=%s -tid --name=node1 busybox" % (calico_port, ip1))
        host1_listen(_in="%s docker run -e CALICO_IP=%s -tid --name=node2 busybox" % (calico_port, ip2))

        # Perform a docker inspect to extract the configured IP addresses.
        node1_ip = host1_exec("%s docker inspect --format '{{ .NetworkSettings.IPAddress }}' node1" % calico_port).stdout.rstrip()
        node2_ip = host1_exec("%s docker inspect --format '{{ .NetworkSettings.IPAddress }}' node2" % calico_port).stdout.rstrip()

        # Configure the nodes with the same profiles.
        host1_listen(_in=calicoctl % "profile TEST_GROUP member add node1")
        host1_listen(_in=calicoctl % "profile TEST_GROUP member add node2")

        node1_pid = host1_exec("docker inspect --format {{.State.Pid}} node1").stdout.rstrip()
        node2_pid = host1_exec("docker inspect --format {{.State.Pid}} node2").stdout.rstrip()

        print "Wait for network to come up"
        for i in range(10):
            try:
                host1_listen(_in="./nsenter -t %s ping %s -c 1 -W 1" % (node1_pid, node2_ip))
                break
            except sh.ErrorReturnCode:
                if i == 9:
                    raise AssertionError
                else:
                    sleep(1)

        # Check connectivity.
        host1_exec("./nsenter -t %s ping %s -c 1" % (node1_pid, node1_ip))
        host1_exec("./nsenter -t %s ping %s -c 1" % (node1_pid, node2_ip))
        host1_exec("./nsenter -t %s ping %s -c 1" % (node2_pid, node1_ip))
        host1_exec("./nsenter -t %s ping %s -c 1" % (node2_pid, node2_ip))

        # Test calicoctl teardown commands.
        host1_exec(calicoctl % "profile remove TEST_GROUP")
        host1_exec(calicoctl % "container remove node1")
        host1_exec(calicoctl % "container remove node2")
        host1_exec(calicoctl % "pool remove 192.168.0.0/16")
        host1_exec(calicoctl % "node stop")


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
