from unittest import TestCase
from docker_host import DockerHost
import sh
from sh import docker


class TestBase(TestCase):
    """Base class for test-wide methods."""
    def setUp(self):
        """
        Clean up host containers before every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            DockerHost.delete_container(container)

        self.start_etcd()

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            DockerHost.delete_container(container)

    def start_etcd(self):
        """
        Starts a separate etcd container.
        """

        self.ip = getattr(self, 'ip', self.get_ip())
        docker.run("-d",
                   "-p", "2379:2379",
                   "--name", "etcd", "quay.io/coreos/etcd:v2.0.10",
                   name="calico",
                   advertise_client_urls="http://%s:2379" % self.ip,
                   listen_client_urls="http://0.0.0.0:2379",
                   initial_advertise_peer_urls="http://%s:2380" % self.ip,
                   listen_peer_urls="http://0.0.0.0:2380",
                   initial_cluster_token="etcd-cluster-2",
                   initial_cluster="calico=http://%s:2380" % self.ip,
                   initial_cluster_state="new")

    def get_ip(self):
        intf = sh.ifconfig.eth0()
        return sh.perl(intf, "-ne", 's/dr:(\S+)/print $1/e')
