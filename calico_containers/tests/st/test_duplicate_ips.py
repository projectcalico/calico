import unittest
from subprocess import CalledProcessError
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestDuplicateIps(TestBase):

    @unittest.skip("Docker driver doesn't support static IP assignment yet.")
    def test_duplicate_ips(self):
        """
        Start two workloads with the same IP on different hosts. Make sure they
        can be reached from all places even after one of them is deleted.
        """
        with DockerHost('host1') as host1, \
             DockerHost('host2') as host2, \
             DockerHost('host3') as host3:

            # Set up three workloads on three hosts
            host1.execute("docker run -e CALICO_IP=192.168.1.1 "
                          "--name workload1 -tid busybox")
            host2.execute("docker run -e CALICO_IP=192.168.1.2 "
                          "--name workload2 -tid busybox")
            host3.execute("docker run -e CALICO_IP=192.168.1.3 "
                          "--name workload3 -tid busybox")

            # Set up the workloads with duplicate IPs
            host1.execute("docker run -e CALICO_IP=192.168.1.4 "
                          "--name dup1 -tid busybox")
            host2.execute("docker run -e CALICO_IP=192.168.1.4 "
                          "--name dup2 -tid busybox")

            host1.calicoctl("profile add TEST_PROFILE")

            # Add everyone to the same profile
            host1.calicoctl("profile TEST_PROFILE member add workload1")
            host1.calicoctl("profile TEST_PROFILE member add dup1")
            host2.calicoctl("profile TEST_PROFILE member add workload2")
            host2.calicoctl("profile TEST_PROFILE member add dup2")
            host3.calicoctl("profile TEST_PROFILE member add workload3")

            # Wait for the workload networking to converge.
            ping = partial(host1.execute,
                           "docker exec workload1 ping -c 4 192.168.1.4")
            retry_until_success(ping, ex_class=CalledProcessError)

            # Check for standard connectivity
            host1.execute("docker exec workload1 ping -c 4 192.168.1.4")
            host2.execute("docker exec workload2 ping -c 4 192.168.1.4")
            host3.execute("docker exec workload3 ping -c 4 192.168.1.4")

            # Delete one of the duplciates.
            host2.execute("docker rm -f dup2")

            # Wait for the workload networking to converge.
            retry_until_success(ping, ex_class=CalledProcessError)

            # Check standard connectivity still works.
            host1.execute("docker exec workload1 ping -c 4 192.168.1.4")
            host2.execute("docker exec workload2 ping -c 4 192.168.1.4")
            host3.execute("docker exec workload3 ping -c 4 192.168.1.4")
