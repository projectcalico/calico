import sh
from sh import docker

from utils import get_ip, delete_container


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

        self.execute("while ! docker ps; do sleep 1; done && "
                     "docker load --input /code/calico_containers/calico-node.tar && "
                     "docker load --input /code/calico_containers/busybox.tar && "
                     "docker load --input /code/calico_containers/nsenter.tar")

    def execute(self, command, docker_host=False, **kwargs):
        """
        Pass a command into a host container.
        """
        stdin = ' '.join(["export ETCD_AUTHORITY=%s:2379;" % get_ip(), command])
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
        delete_container(self.name)
