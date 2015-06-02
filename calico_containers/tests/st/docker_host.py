import sh
from sh import docker, ErrorReturnCode
from functools import partial

from utils import get_ip, delete_container, retry_until_success
from workload import Workload


class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name, start_calico=True):
        """
        Create a container using an image made for docker-in-docker. Load saved images into it.
        """
        self.name = name

        pwd = sh.pwd().stdout.rstrip()
        docker.run("--privileged", "-v", pwd+":/code", "--name", self.name, "-tid", "jpetazzo/dind")

        self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                 self.name).stdout.rstrip()

        # Make sure docker is up
        docker_ps = partial(self.execute, "docker ps")
        retry_until_success(docker_ps, ex_class=ErrorReturnCode)
        self.execute("docker load --input /code/calico_containers/calico-node.tar && "
                     "docker load --input /code/calico_containers/busybox.tar")

        if start_calico:
            self.start_calico_node()
            self.assert_powerstrip_up()

    def delete(self):
        """
        Have a container delete itself.
        """
        delete_container(self.name)

    def _listen(self, stdin, **kwargs):
        """
        Feed a raw command to a container via stdin.
        """
        return docker("exec", "--interactive", self.name,
                      "bash", s=True, _in=stdin, **kwargs)

    def execute(self, command, use_powerstrip=False, **kwargs):
        """
        Pass a command into a host container. Appends some environment
        variables and then calls out to DockerHost._listen. This uses stdin via
        'bash -s' which is more forgiving of bash syntax than 'bash -c'.

        :param use_powerstrip: When true this sets the DOCKER_HOST env var. This
        routes through Powerstrip, so that Calico can be informed of the changes.
        """
        etcd_auth = "export ETCD_AUTHORITY=%s:2379;" % get_ip()
        stdin = ' '.join([etcd_auth, command])

        if use_powerstrip:
            docker_host = "export DOCKER_HOST=localhost:2377;"
            stdin = ' '.join([docker_host, stdin])
        return self._listen(stdin, **kwargs)

    def calicoctl(self, command, **kwargs):
        calicoctl = "/code/dist/calicoctl %s"
        return self.execute(calicoctl % command, **kwargs)

    def start_calico_node(self, ip=None, ip6=None):
        ip = ip or self.ip
        args = ['node', '--ip=%s' % ip]
        if ip6:
            args.append('--ip6=%s' % ip6)
        cmd = ' '.join(args)
        self.calicoctl(cmd)

    def assert_powerstrip_up(self):
        """
        Check that powerstrip is up by running 'docker ps' through port 2377.
        """
        powerstrip = partial(self.execute, "docker ps", use_powerstrip=True)
        retry_until_success(powerstrip, ex_class=ErrorReturnCode)

    def create_workload(*args, **kwargs):
        return Workload(*args, **kwargs)
