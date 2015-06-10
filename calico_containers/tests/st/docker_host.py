import sh
from sh import docker
from functools import partial
from subprocess import check_output, CalledProcessError
from calico_containers.tests.st import utils

from utils import get_ip, retry_until_success
from workload import Workload
from network import DockerNetwork


CALICO_DRIVER_SOCK = "/usr/share/docker/plugins/calico.sock"

class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by
    Calico.
    """
    def __init__(self, name, start_calico=True, dind=True):
        self.name = name
        self.dind = dind

        # This variable is used to assert on destruction that this object was
        # cleaned up.  If not used as a context manager, users of this object
        self._cleaned = False

        if dind:
            # Since `calicoctl node` doesn't fix ipv6 forwarding and module
            # loading, we must manually fix it
            # try:
            #     self.calicoctl("checksystem --fix 2>&1")
            # except CalledProcessError as err:
            #     print "%s \nReturned: %s\nRC: %d\n" % (err.cmd,
            #                                            err.output,
            #                                            err.returncode)

            docker.rm("-f", self.name, _ok_code=[0, 1])
            pwd = sh.pwd().stdout.rstrip()
            docker.run("--privileged", "-v", pwd+":/code", "--name", self.name,
                       "-tid", "calico/dind")
            self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                     self.name).stdout.rstrip()

            self.ip6 = docker.inspect("--format",
                                      "{{ .NetworkSettings."
                                      "GlobalIPv6Address }}",
                                      self.name).stdout.rstrip()

            # Make sure docker is up
            docker_ps = partial(self.execute, "docker ps")
            retry_until_success(docker_ps, ex_class=CalledProcessError)
            self.execute("docker load --input /code/calico_containers/calico-node.tar && "
                         "docker load --input /code/calico_containers/busybox.tar")
        else:
            self.ip = utils.get_ip()

        if start_calico:
            self.start_calico_node()
            self.assert_driver_up()

    def execute(self, command, **kwargs):
        """
        Pass a command into a host container.
        """
        etcd_auth = "ETCD_AUTHORITY=%s:2379 " % get_ip()
        command = "%s %s" % (etcd_auth, command)

        if self.dind:
            # TODO - work out what was wrong with the bash -s approach and fix
            command = command.replace('\'', '\'"\'"\'')
            command = "docker exec -it %s bash -c '%s'" % (self.name,
                                                              command)
        return check_output(command, shell=True)

    def calicoctl(self, command, **kwargs):
        """
        Convenience function for abstracting away calling the calicoctl
        command.
        """
        if self.dind:
            calicoctl = "/code/dist/calicoctl %s"
        else:
            calicoctl = "dist/calicoctl %s"
        return self.execute(calicoctl % command, **kwargs)

    def start_calico_node(self):
        """
        Start calico in a container inside a host by calling through to the
        calicoctl node command.
        """
        args = ['node', '--ip=%s' % self.ip]
        if self.ip6:
            args.append('--ip6=%s' % self.ip6)
        cmd = ' '.join(args)
        self.calicoctl(cmd)

    def assert_driver_up(self):
        """
        Check that Calico Docker Driver is up by checking the existence of
        the unix socket.
        """
        sock_exists = partial(self.execute,
                              "[ -e %s ]" % CALICO_DRIVER_SOCK)
        retry_until_success(sock_exists, ex_class=CalledProcessError)

    def remove_containers(self):
        """
        Remove all containers running on this host.

        Useful for test shut down to ensure the host is cleaned up.
        :return: None
        """
        # TODO: only remove ST created containers for non-dind.
        cmd = "docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)"
        ok_codes = [0,
                    1,  # docker: "rm" requires a minimum of 1 argument.
                    127,  # '"docker": no command found'
                    255,  # '"bash": executable file not found in $PATH'
                    ]
        try:
            self.execute(cmd)
        except CalledProcessError as err:
            if err.returncode not in ok_codes:
                raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context of this host.
        :return: None
        """
        self.cleanup()

    def cleanup(self):
        """
        Clean up this host, including removing any containers is created.  This
        is necessary especially for Docker-in-Docker so we don't leave dangling
        volumes.
        :return:
        """
        self.remove_containers()
        if self.dind:
            # For docker in docker we also need to remove the outer container.
            docker.rm("-f", self.name, _ok_code=[0, 1])
        self._cleaned = True

    def __del__(self):
        """
        This destructor asserts this object was cleaned up before being GC'd.

        Why not just clean up?  This object is used in test scripts and we
        can't guarantee that GC will happen between test runs.  So, un-cleaned
        objects may result in confusing behaviour since this object manipulates
        Docker containers running on the system.
        :return:
        """
        assert self._cleaned

    def create_workload(self, name, ip=None, image="busybox", network=None):
        """
        Create a workload container inside this host container.
        """
        return Workload(self, name, ip=ip, image=image, network=network)

    def create_network(self, name, driver="calico"):
        """
        Create a Docker network using this host.

        :param name: The name of the network.  This must be unique per cluster
        and it the user-facing identifier for the network.  (Calico itself will
        get a UUID for the network via the driver API and will not get the
        name).
        :param driver: The name of the network driver to use.  (The Calico
        driver is the default.)
        :return: A DockerNetwork object.
        """
        return DockerNetwork(self, name, driver=driver)
