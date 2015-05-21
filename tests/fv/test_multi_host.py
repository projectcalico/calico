from test_base import TestBase
from time import sleep
from sh import docker, ErrorReturnCode_1
from docker_host import DockerHost


class MultiHostMainline(TestBase):
    def test_multi_host(self):
        """
        Run a mainline multi-host test. Almost identical in function to the vagrant coreOS demo.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')
        host1.start_etcd()

        host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", host1.name).stdout.rstrip()
        host2_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", host2.name).stdout.rstrip()

        etcd_port = "ETCD_AUTHORITY=%s:2379" % host1_ip
        calicoctl = etcd_port + " /code/dist/calicoctl %s"

        host1.listen(calicoctl % "reset || true")

        host1.listen(calicoctl % ("node --ip=%s" % host1_ip))
        host2.listen(calicoctl % ("node --ip=%s" % host2_ip))

        calico_port = "DOCKER_HOST=localhost:2377"

        # Wait for the Calico nodes to be created.
        sleep(1)

        host1.listen("%s docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox" % (calico_port))
        host1.listen("%s docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox" % (calico_port))
        host1.listen("%s docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox" % (calico_port))

        host2.listen("%s docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox" % (calico_port))
        host2.listen("%s docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox" % (calico_port))

        host1.listen(calicoctl % "profile add PROF_A_C_E")
        host1.listen(calicoctl % "profile add PROF_B")
        host1.listen(calicoctl % "profile add PROF_D")

        host1.listen(calicoctl % "profile PROF_A_C_E member add workload-A")
        host1.listen(calicoctl % "profile PROF_B member add workload-B")
        host1.listen(calicoctl % "profile PROF_A_C_E member add workload-C")

        host2.listen(calicoctl % "profile PROF_D member add workload-D")
        host2.listen(calicoctl % "profile PROF_A_C_E member add workload-E")

        # Wait for the workload networking to converge.
        sleep(1)

        host1.execute("docker exec workload-A ping -c 4 192.168.1.3")

        try:
            host1.execute("docker exec workload-A ping -c 4 192.168.1.2")
            raise
        except ErrorReturnCode_1:
            pass

        try:
            host1.execute("docker exec workload-A ping -c 4 192.168.1.4")
            raise
        except ErrorReturnCode_1:
            pass

        host1.execute("docker exec workload-A ping -c 4 192.168.1.5")
