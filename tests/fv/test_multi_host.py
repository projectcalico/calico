import unittest
from time import sleep
import sh
from sh import docker


class MultiHostMainline(unittest.TestCase):
    def test_multi_host(self):
        docker_exec = docker.bake("exec")

        host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host1").stdout.rstrip()
        host2_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host2").stdout.rstrip()

        calicoctl = "/code/dist/calicoctl"
        etcd_port = "ETCD_AUTHORITY=%s:2379" % host1_ip
        host1_listen = docker_exec.bake("-i", "host1", "bash", "-s")
        host2_listen = docker_exec.bake("-i", "host2", "bash", "-s")

        host1_listen(_in="%s %s reset || true" % (etcd_port, calicoctl))

        host1_listen(_in="%s %s node --ip=%s" % (etcd_port, calicoctl, host1_ip))
        host2_listen(_in="%s %s node --ip=%s" % (etcd_port, calicoctl, host2_ip))

        calico_port = "DOCKER_HOST=localhost:2377"

        sleep(1)

        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox" % (calico_port))
        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox" % (calico_port))
        host1_listen(_in="%s docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox" % (calico_port))

        host2_listen(_in="%s docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox" % (calico_port))
        host2_listen(_in="%s docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox" % (calico_port))

        host1_listen(_in="%s %s profile add PROF_A_C_E" % (etcd_port, calicoctl))
        host1_listen(_in="%s %s profile add PROF_B" % (etcd_port, calicoctl))
        host1_listen(_in="%s %s profile add PROF_D" % (etcd_port, calicoctl))

        host1_listen(_in="%s %s profile PROF_A_C_E member add workload-A" % (etcd_port, calicoctl))
        host1_listen(_in="%s %s profile PROF_B member add workload-B" % (etcd_port, calicoctl))
        host1_listen(_in="%s %s profile PROF_A_C_E member add workload-C" % (etcd_port, calicoctl))

        host2_listen(_in="%s %s profile PROF_D member add workload-D" % (etcd_port, calicoctl))
        host2_listen(_in="%s %s profile PROF_A_C_E member add workload-E" % (etcd_port, calicoctl))

        sleep(1)

        host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")

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
