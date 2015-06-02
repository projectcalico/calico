from sh import ErrorReturnCode_1
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestDuplicateIps(TestBase):
    def test_duplicate_ips(self):
        """
        Start two workloads with the same IP on different hosts. Make sure they
        can be reached from all places even after one of them is deleted.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')
        host3 = DockerHost('host3')

        # Set up three workloads on three hosts
        host1.execute("docker run -e CALICO_IP=192.168.1.1 --name workload1 -tid busybox",
                      use_powerstrip=True)
        host2.execute("docker run -e CALICO_IP=192.168.1.2 --name workload2 -tid busybox",
                      use_powerstrip=True)
        host3.execute("docker run -e CALICO_IP=192.168.1.3 --name workload3 -tid busybox",
                      use_powerstrip=True)

        # Set up the workloads with duplicate IPs
        host1.execute("docker run -e CALICO_IP=192.168.1.4 --name dup1 -tid busybox",
                      use_powerstrip=True)
        host2.execute("docker run -e CALICO_IP=192.168.1.4 --name dup2 -tid busybox",
                      use_powerstrip=True)

        host1.calicoctl("profile add TEST_PROFILE")

        # Add everyone to the same profile
        host1.calicoctl("profile TEST_PROFILE member add workload1")
        host1.calicoctl("profile TEST_PROFILE member add dup1")
        host2.calicoctl("profile TEST_PROFILE member add workload2")
        host2.calicoctl("profile TEST_PROFILE member add dup2")
        host3.calicoctl("profile TEST_PROFILE member add workload3")

        # Wait for the workload networking to converge.
        ping = partial(host1.execute, "docker exec workload1 ping -c 4 192.168.1.4")
        retry_until_success(ping, ex_class=ErrorReturnCode_1)

        # Check for standard connectivity
        host1.execute("docker exec workload1 ping -c 4 192.168.1.4")
        host2.execute("docker exec workload2 ping -c 4 192.168.1.4")
        host3.execute("docker exec workload3 ping -c 4 192.168.1.4")

        # Delete one of the duplciates.
        host2.execute("docker rm -f dup2")

        # Wait for the workload networking to converge.
        retry_until_success(ping, ex_class=ErrorReturnCode_1)

        # Check standard connectivity still works.
        host1.execute("docker exec workload1 ping -c 4 192.168.1.4")
        host2.execute("docker exec workload2 ping -c 4 192.168.1.4")
        host3.execute("docker exec workload3 ping -c 4 192.168.1.4")
