import sh
from sh import docker, ErrorReturnCode
from functools import partial
from subprocess import check_output

from utils import get_ip, delete_container, retry_until_success


CALICO_DRIVER_SOCK = "/usr/share/docker/plugins/calico.sock"

class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name, start_calico=True):
        self.name = name

        docker.rm("-f", self.name, _ok_code=[0, 1])
        pwd = sh.pwd().stdout.rstrip()
        print "Running host"
        docker.run("--privileged", "-v", pwd+":/code", "--name", self.name,
                   "-tid", "jpetazzo/dind")
        print "Run host"
        self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                 self.name).stdout.rstrip()

        ip6 = docker.inspect("--format", "{{ .NetworkSettings.GlobalIPv6Address }}",
                             self.name).stdout.rstrip()
        # TODO: change this hardcoding when we set up IPv6 for hosts
        self.ip6 = ip6 or "fd80:24e2:f998:72d6::1"

        ### TEMP CODE ###
        # Make sure the existing docker daemon is stopped and run the new one (if
        # it's not already running)
        self.execute("pkill docker")
        check_output("docker exec -dit %s bash -c '/code/docker-dev -dD "
                     ">/tmp/docker.log 2>/tmp/docker.err.log'" % self.name,
                     shell=True)
        self.execute("ln -sf /code/docker-dev /usr/local/bin/docker")

        # Make sure docker is up
        docker_ps = partial(self.execute, "docker ps")
        retry_until_success(docker_ps, ex_class=ErrorReturnCode)
        self.execute("docker load --input /code/calico_containers/calico-node.tar && "
                     "docker load --input /code/calico_containers/busybox.tar")

        if start_calico:
            print "Starting node"
            self.start_calico_node()
            print "Started node"
            self.assert_driver_up()
            print "Driver is up"


    def delete(self):
        """
        Have a container delete itself.
        """
        delete_container(self.name)

    def execute(self, command, **kwargs):
        """
        Pass a command into a host container.
        """
        etcd_auth = "ETCD_AUTHORITY=%s:2379 " % get_ip()
        full_command = "docker exec -it %s bash -c '%s %s'" % (self.name,
                                                               etcd_auth,
                                                               command)
        print "command: %s" % full_command
        return check_output(full_command, shell=True)

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
