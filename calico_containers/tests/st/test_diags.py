from test_base import TestBase
from docker_host import DockerHost


class TestDiags(TestBase):
    def test_diags(self):
        """
        Test that the diags command successfully uploads the diags file.
        """
        host = DockerHost('host', start_calico=False)
        link = host.calicoctl("diags")
        self.assertIn("https://transfer.sh/", link)
