import unittest
from time import sleep
import sh
from sh import docker


class MultiHostMainline(unittest.TestCase):
    def test_multi_host(self):
        """
        Run a mainline multi-host test. Almost identical in function to the vagrant coreOS demo.
        """
        docker_exec = docker.bake("exec")
        host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")

        host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host1").stdout.rstrip()
        host2_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host2").stdout.rstrip()

        etcd_port = "ETCD_AUTHORITY=%s:2379" % host1_ip
        calicoctl = etcd_port + " /code/dist/calicoctl %s"
        host1_listen = docker_exec.bake("-i", "host1", "bash", "-s")
        host2_listen = docker_exec.bake("-i", "host2", "bash", "-s")

        host1_listen(_in=calicoctl % "reset || true")

        host1_listen(_in=calicoctl % ("node --ip=%s" % host1_ip))
        host2_listen(_in=calicoctl % ("node --ip=%s" % host2_ip))

        calico_port = "DOCKER_HOST=localhost:2377"

        # Wait for the Calico nodes to be created.
        sleep(1)

        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox" % (calico_port))
        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox" % (calico_port))
        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox" % (calico_port))

        host2_listen(_in="%s docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox" % (calico_port))
        host2_listen(_in="%s docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox" % (calico_port))

        host1_listen(_in=calicoctl % "profile add PROF_A_C_E")
        host1_listen(_in=calicoctl % "profile add PROF_B")
        host1_listen(_in=calicoctl % "profile add PROF_D")

        host1_listen(_in=calicoctl % "profile PROF_A_C_E member add workload-A")
        host1_listen(_in=calicoctl % "profile PROF_B member add workload-B")
        host1_listen(_in=calicoctl % "profile PROF_A_C_E member add workload-C")

        host2_listen(_in=calicoctl % "profile PROF_D member add workload-D")
        host2_listen(_in=calicoctl % "profile PROF_A_C_E member add workload-E")

        # Wait for the workload networking to converge.
        sleep(1)


        host1_exec("docker exec workload-A ping -c 4 192.168.1.3")

        try:
            host1_exec("docker exec workload-A ping -c 4 192.168.1.2")
            raise
        except sh.ErrorReturnCode_1:
            pass

        try:
            host1_exec("docker exec workload-A ping -c 4 192.168.1.4")
            raise
        except sh.ErrorReturnCode_1:
            pass

        host1_exec("docker exec workload-A ping -c 4 192.168.1.5")
