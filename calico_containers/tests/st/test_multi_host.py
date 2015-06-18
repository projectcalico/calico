import unittest
import uuid

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost


class MultiHostMainline(TestBase):

    @unittest.skip("Libnetwork doesn't support multi-host yet.")
    def test_multi_host(self):
        """
        Run a mainline multi-host test.

        Almost identical in function to the vagrant coreOS demo.
        """
        with DockerHost('host1') as host1, DockerHost('host2') as host2:

            net135 = host1.create_network(str(uuid.uuid4()))
            net2 = host1.create_network(str(uuid.uuid4()))
            net4 = host1.create_network(str(uuid.uuid4()))

            workload1 = host1.create_workload("workload1", network=net135)
            workload2 = host1.create_workload("workload2", network=net2)
            workload3 = host1.create_workload("workload3", network=net135)

            workload4 = host2.create_workload("workload4", network=net4)
            workload5 = host2.create_workload("workload5", network=net135)

            self.assert_connectivity(pass_list=[workload1,
                                                workload3,
                                                workload5],
                                     fail_list=[workload2,
                                                workload4])

            self.assert_connectivity(pass_list=[workload2],
                                     fail_list=[workload1,
                                                workload3,
                                                workload4,
                                                workload5])

            self.assert_connectivity(pass_list=[workload4],
                                     fail_list=[workload1,
                                                workload2,
                                                workload3,
                                                workload5])
