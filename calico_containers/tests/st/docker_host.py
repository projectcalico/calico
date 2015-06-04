import sh
from sh import docker, ErrorReturnCode
from functools import partial

from utils import get_ip, delete_container, retry_until_success


CALICO_DRIVER_SOCK = "/usr/share/docker/plugins/calico.sock"

class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name, start_calico=True):
        self.name = name

        pwd = sh.pwd().stdout.rstrip()
        docker.run("--privileged", "-v", pwd+":/code", "--name", self.name,
                   "-tid", "calico/host")

        self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                 self.name).stdout.rstrip()

        ip6 = docker.inspect("--format", "{{ .NetworkSettings.GlobalIPv6Address }}",
                             self.name).stdout.rstrip()
        # TODO: change this hardcoding when we set up IPv6 for hosts
        self.ip6 = ip6 or "fd80:24e2:f998:72d6::1"

        if start_calico:
            self.start_calico_node()
            self.assert_driver_up()

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

    def execute(self, command, **kwargs):
        """
        Pass a command into a host container. Appends some environment
        variables and then calls out to DockerHost._listen. This uses stdin via
        'bash -s' which is more forgiving of bash syntax than 'bash -c'.

        """
        etcd_auth = "export ETCD_AUTHORITY=%s:2379;" % get_ip()
        stdin = ' '.join([etcd_auth, command])

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

    def assert_driver_up(self):
        """
        Check that Calico Docker Driver is up by checking the existence of
        the unix socket.
        """
        sock_exists = partial(self.execute, "/bin/sh", "-c",
                              '"[ -e %s ]"' % CALICO_DRIVER_SOCK)
        retry_until_success(sock_exists, ex_class=ErrorReturnCode)
