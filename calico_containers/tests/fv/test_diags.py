from test_base import TestBase
from docker_host import DockerHost


class TestDiags(TestBase):
    def test_diags(self):
        """
        Test that the diags command successfully uploads the diags file.
        """
        host = DockerHost('host')
        link = host.execute("/code/dist/calicoctl diags")
        assert "https://transfer.sh/" in link
