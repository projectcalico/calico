from nose.plugins.attrib import attr

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost


class TestDiags(TestBase):
    @attr('slow')
    def test_diags(self):
        """
        Test that the diags command successfully uploads the diags file.
        """
        with DockerHost('host', start_calico=False) as host:
            results = host.calicoctl("diags")
            self.assertIn(".tar.gz", results)

