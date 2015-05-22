from sh import docker, ErrorReturnCode
from time import sleep
from functools import partial

from unittest import TestCase
from docker_host import DockerHost


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
            DockerHost.delete_container(container)

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            DockerHost.delete_container(container)

    def retry_until_success(self, function, retries=10, ex_class=None):
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
            except Exception as e:
                if ex_class and not issubclass(e.__class__, ex_class):
                    raise
                if retry < retries:
                    sleep(1)
                else:
                    raise
            else:
                # Successfully ran the function
                return result

    def assert_powerstrip_up(self, host):
        powerstrip = partial(host.execute, "docker ps", docker_host=True)
        self.retry_until_success(powerstrip, ex_class=ErrorReturnCode)
