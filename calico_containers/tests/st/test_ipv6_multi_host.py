import unittest
from test_base import TestBase
from docker_host import DockerHost


class Ipv6MultiHostMainline(TestBase):

    @unittest.skip("Don't support IPv6 multi-host yet.")
    def test_ipv6_multi_host(self):
        """
        Run a mainline multi-host test with IPv6.

        Almost identical in function to the vagrant coreOS demo.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')

        ip1 = "fd80:24e2:f998:72d6::1:1"
        ip2 = "fd80:24e2:f998:72d6::1:2"
        ip3 = "fd80:24e2:f998:72d6::1:3"
        ip4 = "fd80:24e2:f998:72d6::1:4"
        ip5 = "fd80:24e2:f998:72d6::1:5"

        # We use this image here because busybox doesn't have ping6.
        workload1 = host1.create_workload("workload1", ip1, image="phusion/baseimage:0.9.16")
        workload2 = host1.create_workload("workload2", ip2, image="phusion/baseimage:0.9.16")
        workload3 = host1.create_workload("workload3", ip3, image="phusion/baseimage:0.9.16")

        workload4 = host2.create_workload("workload4", ip4, image="phusion/baseimage:0.9.16")
        workload5 = host2.create_workload("workload5", ip5, image="phusion/baseimage:0.9.16")

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
