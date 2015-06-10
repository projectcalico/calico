import requests
from sh import docker
from subprocess import CalledProcessError
from unittest import TestCase

from utils import get_ip


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up host containers before every test.
        """
        # containers = docker.ps("-qa").split()
        # for container in containers:
        #     delete_container(container)

        self.ip = get_ip()
        self.start_etcd()

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        # containers = docker.ps("-qa").split()
        # for container in containers:
        #     delete_container(container)
        # import sh
        # docker.rm("-f", "etcd", _ok_code=[0, 1])

    def start_etcd(self):
        """
        Starts the single-node etcd cluster.

        The etcd process runs within its own container, outside the host
        containers. It uses port mapping and the base machine's IP to communicate.
        """
        docker.rm("-f", "etcd", _ok_code=[0, 1])
        docker.run(
            "--detach",
            "--publish", "2379:2379",
            "--publish", "2380:2380",
            "--name", "etcd", "quay.io/coreos/etcd:v2.0.11",
            name="calico",
            advertise_client_urls="http://%s:2379" % self.ip,
            listen_client_urls="http://0.0.0.0:2379",
            initial_advertise_peer_urls="http://%s:2380" % self.ip,
            listen_peer_urls="http://0.0.0.0:2380",
            initial_cluster_token="etcd-cluster-2",
            initial_cluster="calico=http://%s:2380" % self.ip,
            initial_cluster_state="new",
        )

        # TODO - talking to etcd fails until a request is made from outside
        # the dind to etcd. Not sure why yet...
        requests.get("http://%s:2379/version" % self.ip)

    def assert_connectivity(self, pass_list, fail_list=[]):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        """
        for source in pass_list:
            for dest in pass_list:
                source.assert_can_ping(dest.ip)
            for dest in fail_list:
                with self.assertRaises(CalledProcessError):
                    source.assert_can_ping(dest.ip)
