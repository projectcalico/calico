from time import sleep
import unittest

from test_base import TestBase
from docker_host import DockerHost


@unittest.skip("Haven't fixed because command is deprecated.")
class TestUnixSocket(TestBase):
    def test_unix_socket(self):
        host = DockerHost('host')

        calicoctl = "sudo /code/dist/calicoctl %s"

        host._listen(calicoctl % "restart-docker-without-alternative-unix-socket")

        # host.start_etcd(restart="always")
        host._listen("docker run --restart=always -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10")

        # Run without the unix socket. Check that docker can be accessed though both
        # the unix socket and the powerstrip TCP port.
        host._listen(calicoctl % "node --ip=127.0.0.1")
        host._listen("docker ps")
        self.assert_powerstrip_up(host)

        # Run with the unix socket. Check that docker can be access through both
        # unix sockets.
        # TODO: Currently hangs here.
        host._listen(calicoctl % "restart-docker-with-alternative-unix-socket")
        # etcd is running under docker, so wait for it to come up.
        sleep(5)
        host._listen(calicoctl % "node --ip=127.0.0.1")
        host._listen("docker ps")

        # Switch back to without the unix socket and check that everything still works.
        host._listen(calicoctl % "restart-docker-without-alternative-unix-socket")
        # etcd is running under docker, so wait for it to come up.
        sleep(5)
        host._listen(calicoctl % "node --ip=127.0.0.1")
        host._listen("docker ps")
        self.assert_powerstrip_up(host)
