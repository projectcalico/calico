import sh
from sh import docker


class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name):
        """
        Create a container using an image made for docker-in-docker. Load saved images into it.
        """
        self.name = name

        pwd = sh.pwd().stdout.rstrip()
        docker.run("--privileged", "-v", pwd+":/code", "--name", self.name, "-tid", "jpetazzo/dind")

        self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                 self.name).stdout.rstrip()
        self.execute("while ! docker ps; do sleep 1; done && "
                   "docker load --input /code/calico-node.tar && "
                   "docker load --input /code/busybox.tar && "
                   "docker load --input /code/nsenter.tar")

    def execute(self, command, docker_host=False, **kwargs):
        """
        Pass a command into a host container.
        """
        stdin = ' '.join(["export ETCD_AUTHORITY=%s:2379;" % self.ip, command])
        if docker_host:
            stdin = ' '.join(["export DOCKER_HOST=localhost:2377;", stdin])
        return self.listen(stdin, **kwargs)

    def listen(self, stdin, **kwargs):
        """
        Feed a command to a container via stdin. Used when `bash -c` in
        DockerHost.execute has bad parsing behavior.
        """
        return docker("exec", "-i", self.name, "bash", s=True, _in=stdin, **kwargs)

    def delete(self):
        """
        Have a container delete itself.
        """
        self.__class__.delete_container(self.name)

    def start_etcd(self):
        """
        Start etcd on this host. Not tested for multiple etcd nodes. Start etcd
        only after all hosts have been created.
        """
        self.execute("docker load --input /code/etcd.tar")

        cmd = ("--name calico "
               "--advertise-client-urls http://%s:2379 "
               "--listen-client-urls http://0.0.0.0:2379 "
               "--initial-advertise-peer-urls http://%s:2380 "
               "--listen-peer-urls http://0.0.0.0:2380 "
               "--initial-cluster-token etcd-cluster-2 "
               "--initial-cluster calico=http://%s:2380 "
               "--initial-cluster-state new" % (self.ip, self.ip, self.ip))
        self.execute("docker run -d -p 2379:2379 quay.io/coreos/etcd:v2.0.10 %s" % cmd)

    @classmethod
    def delete_container(cls, name):
        """
        Cleanly delete a container.
        """
        # We *must* remove all inner containers and images before removing the outer
        # container. Otherwise the inner images will stick around and fill disk.
        # https://github.com/jpetazzo/dind#important-warning-about-disk-usage
        cls.cleanup_inside(name)
        sh.docker.rm("-f", name, _ok_code=[0, 1])

    @classmethod
    def cleanup_inside(cls, name):
        """
        Clean the inside of a container by deleting the containers and images within it.
        """
        docker("exec", "-t", name, "bash", "-c",
               "docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)",
               _ok_code=[0,
                         1,  # Caused by 'docker: "rm" requires a minimum of 1 argument.' et al.
                         127,  # Caused by '"docker": no command found'
                         255,  # Caused by '"bash": executable file not found in $PATH'
                         ]
               )
