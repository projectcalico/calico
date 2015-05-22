from sh import docker, ErrorReturnCode
from functools import partial

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

        self.assert_powerstrip_up(host)

        host.execute(calicoctl % "container add node 192.168.1.1")
        host.execute(calicoctl % "profile TEST_GROUP member add node")

        # Wait for felix to program down the route.
        powerstrip = partial(host.execute, "ip route | grep '192\.168\.1\.1'")
        self.retry_until_success(powerstrip, ex_class=ErrorReturnCode)
