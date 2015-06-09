from sh import ErrorReturnCode_1
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class MultiHostMainline(TestBase):
    def test_multi_host(self):
        """
        Run a mainline multi-host test.

        Almost identical in function to the vagrant coreOS demo.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')

        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"
        ip4 = "192.168.1.4"
        ip5 = "192.168.1.5"

        workload1 = host1.create_workload("workload1", ip1)
        workload2 = host1.create_workload("workload2", ip2)
        workload3 = host1.create_workload("workload3", ip3)

        workload4 = host2.create_workload("workload4", ip4)
        workload5 = host2.create_workload("workload5", ip5)

        host1.calicoctl("profile add PROF_1_3_5")
        host1.calicoctl("profile add PROF_2")
        host1.calicoctl("profile add PROF_4")

        host1.calicoctl("profile PROF_1_3_5 member add %s" % workload1)
        host1.calicoctl("profile PROF_2 member add %s" % workload2)
        host1.calicoctl("profile PROF_1_3_5 member add %s" % workload3)

        host2.calicoctl("profile PROF_4 member add %s" % workload4)
        host2.calicoctl("profile PROF_1_3_5 member add %s" % workload5)

        self.assert_connectivity(pass_list=[workload1, workload3, workload5],
                                 fail_list=[workload2, workload4])

        self.assert_connectivity(pass_list=[workload2],
                                 fail_list=[workload1, workload3, workload4, workload5])

        self.assert_connectivity(pass_list=[workload4],
                                 fail_list=[workload1, workload2, workload3, workload5])
