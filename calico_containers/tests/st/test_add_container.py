from sh import docker, ErrorReturnCode
from time import sleep

from test_base import TestBase
from docker_host import DockerHost


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        
        """
        host = DockerHost('host')
        host.start_etcd()

        host_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", host.name).stdout.rstrip()
        etcd_port = "ETCD_AUTHORITY=%s:2379" % host_ip
        calicoctl = etcd_port + " /code/dist/calicoctl %s"

        host.listen("docker run -tid --name=node busybox")
        host.execute(calicoctl % "node --ip=127.0.0.1")
        host.execute(calicoctl % "profile add TEST_GROUP")

        # Wait for powerstrip to come up.
        for i in range(5):
            try:
                host.execute("docker ps", docker_host=True)
                break
            except ErrorReturnCode:
                if i == 4:
                    raise AssertionError("Powerstrip failed to come up.")
                else:
                    sleep(1)

        host.execute(calicoctl % "container add node 192.168.1.1")
        host.execute(calicoctl % "profile TEST_GROUP member add node")

        for i in range(10):
            try:
                host.execute("ip route | grep '192\.168\.1\.1'")
                break
            except ErrorReturnCode:
                if i == 9:
                    raise AssertionError("Felix failed to add route.")
                else:
                    sleep(1)
