from subprocess import CalledProcessError
from unittest import TestCase
import subprocess
from calico_containers.tests.st.utils.utils import get_ip


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = get_ip()
        # Delete /calico if it exists. This ensures each test has an empty data
        # store at start of day.
        subprocess.check_output(
            "curl -sL http://%s:2379/v2/keys/calico?recursive=true -XDELETE"
            % self.ip, shell=True)

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
