from sh import docker
from time import sleep
from unittest import TestCase

from utils import get_ip, delete_container


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up host containers before every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            delete_container(container)

        self.ip = get_ip()
        self.start_etcd()

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            delete_container(container)

    def start_etcd(self):
        """
        Starts a separate etcd container.
        """

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

    def retry_until_success(self, function, retries=10, ex_class=Exception):
        """
        Retries function until no exception is thrown. If exception continues,
        it is reraised.

        :param function: the function to be repeatedly called
        :param retries: the maximum number of times to retry the function.
        A value of 0 will run the function once with no retries.
        :param ex_class: The class of expected exceptions.
        :returns: the value returned by function
        """
        for retry in range(retries + 1):
            try:
                result = function()
            except ex_class:
                if retry < retries:
                    sleep(1)
                else:
                    raise
            else:
                # Successfully ran the function
                return result
