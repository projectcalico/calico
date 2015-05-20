import sh
from sh import docker


class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name):
        self.name = name

        docker_exec = docker.bake("exec")
        host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")
        host2_exec = docker_exec.bake("-t", "host2", "bash", "-c")

        # Set up two hosts for the entire test suite to use.
        pwd = sh.pwd().stdout.rstrip()
        docker.run("--privileged", "-v", pwd+":/code", "--name", "host1", "-tid", "jpetazzo/dind")
        docker.run("--privileged", "-v", pwd+":/code", "--name", "host2", "-tid", "jpetazzo/dind")
        print "Host containers created"

        # Load the saved images into the host containers.
        host1_exec("while ! docker ps; do sleep 1; done && "
                   "docker load --input /code/calico-node.tar && "
                   "docker load --input /code/busybox.tar && "
                   "docker load --input /code/nsenter.tar && "
                   "docker load --input /code/etcd.tar")

        host2_exec("while ! docker ps; do sleep 1; done && "
                   "docker load --input /code/calico-node.tar && "
                   "docker load --input /code/busybox.tar && "
                   "docker load --input /code/nsenter.tar")

        # Set up the single-node etcd cluster inside host1.
        host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host1").stdout.rstrip()
        cmd = ("--name calico "
               "--advertise-client-urls http://%s:2379 "
               "--listen-client-urls http://0.0.0.0:2379 "
               "--initial-advertise-peer-urls http://%s:2380 "
               "--listen-peer-urls http://0.0.0.0:2380 "
               "--initial-cluster-token etcd-cluster-2 "
               "--initial-cluster calico=http://%s:2380 "
               "--initial-cluster-state new" % (host1_ip, host1_ip, host1_ip))
        host1_exec('docker run -d -p 2379:2379 quay.io/coreos/etcd:v2.0.10 %s' % cmd)
        print "Etcd container started"
