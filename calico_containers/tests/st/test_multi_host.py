import unittest
from subprocess import CalledProcessError
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class MultiHostMainline(TestBase):

    @unittest.skip("Need Docker-in-Docker with 1.7 network driver support.")
    def test_multi_host(self):
        """
        Run a mainline multi-host test.

        Almost identical in function to the vagrant coreOS demo.
        """
        with DockerHost('host1') as host1, DockerHost('host2') as host2:

            ip1 = "192.168.1.1"
            ip2 = "192.168.1.2"
            ip3 = "192.168.1.3"
            ip4 = "192.168.1.4"
            ip5 = "192.168.1.5"

            host1.execute("docker run -e CALICO_IP=%s "
                          "--name workload1 -tid busybox" % ip1)
            host1.execute("docker run -e CALICO_IP=%s "
                          "--name workload2 -tid busybox" % ip2)
            host1.execute("docker run -e CALICO_IP=%s "
                          "--name workload3 -tid busybox" % ip3)

            host2.execute("docker run -e CALICO_IP=%s "
                          "--name workload4 -tid busybox" % ip4)
            host2.execute("docker run -e CALICO_IP=%s "
                          "--name workload5 -tid busybox" % ip5)

            host1.calicoctl("profile add PROF_1_3_5")
            host1.calicoctl("profile add PROF_2")
            host1.calicoctl("profile add PROF_4")

            host1.calicoctl("profile PROF_1_3_5 member add workload1")
            host1.calicoctl("profile PROF_2 member add workload2")
            host1.calicoctl("profile PROF_1_3_5 member add workload3")

            host2.calicoctl("profile PROF_4 member add workload4")
            host2.calicoctl("profile PROF_1_3_5 member add workload5")

            # Wait for the workload networking to converge.
            ping = partial(host1.execute,
                           "docker exec workload1 ping -c 4 %s" % ip3)
            retry_until_success(ping, ex_class=CalledProcessError)

            with self.assertRaises(CalledProcessError):
                host1.execute("docker exec workload1 ping -c 4 %s" % ip2)

            with self.assertRaises(CalledProcessError):
                host1.execute("docker exec workload1 ping -c 4 %s" % ip4)

            host1.execute("docker exec workload1 ping -c 4 %s" % ip5)
