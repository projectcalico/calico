from unittest import TestCase
from docker_host import DockerHost
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

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            DockerHost.delete_container(container)
