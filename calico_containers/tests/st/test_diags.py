from test_base import TestBase
from docker_host import DockerHost
from nose.plugins.attrib import attr


class TestDiags(TestBase):
    @attr('slow')
    def test_diags(self):
        """
        Test that the diags command successfully uploads the diags file.
        """
        with DockerHost('host', start_calico=False) as host:
            results = host.calicoctl("diags")
            self.assertIn(".tar.gz", results)

