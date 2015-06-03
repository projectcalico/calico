from sh import ErrorReturnCode_1
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


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

        host1.execute("docker run -e CALICO_IP=%s --name workload1 -tid busybox" % ip1,
                      use_powerstrip=True)
        host1.execute("docker run -e CALICO_IP=%s --name workload2 -tid busybox" % ip2,
                      use_powerstrip=True)
        host1.execute("docker run -e CALICO_IP=%s --name workload3 -tid busybox" % ip3,
                      use_powerstrip=True)

        host2.execute("docker run -e CALICO_IP=%s --name workload4 -tid busybox" % ip4,
                      use_powerstrip=True)
        host2.execute("docker run -e CALICO_IP=%s --name workload5 -tid busybox" % ip5,
                      use_powerstrip=True)

        host1.calicoctl("profile add PROF_1_3_5")
        host1.calicoctl("profile add PROF_2")
        host1.calicoctl("profile add PROF_4")

        host1.calicoctl("profile PROF_1_3_5 member add workload1")
        host1.calicoctl("profile PROF_2 member add workload2")
        host1.calicoctl("profile PROF_1_3_5 member add workload3")

        host2.calicoctl("profile PROF_4 member add workload4")
        host2.calicoctl("profile PROF_1_3_5 member add workload5")

        # Wait for the workload networking to converge.
        ping = partial(host1.execute, "docker exec workload1 ping -c 4 %s" % ip3)
        retry_until_success(ping, ex_class=ErrorReturnCode_1)

        with self.assertRaises(ErrorReturnCode_1):
            host1.execute("docker exec workload1 ping -c 4 %s" % ip2)

        with self.assertRaises(ErrorReturnCode_1):
            host1.execute("docker exec workload1 ping -c 4 %s" % ip4)

        host1.execute("docker exec workload1 ping -c 4 %s" % ip5)
