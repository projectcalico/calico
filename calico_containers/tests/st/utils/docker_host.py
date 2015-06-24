import os
import sh
from sh import docker
from functools import partial
from subprocess import check_output, CalledProcessError, STDOUT
from calico_containers.tests.st.utils import utils
from calico_containers.tests.st.utils.utils import retry_until_success, get_ip
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
        self.workloads = set()

        # This variable is used to assert on destruction that this object was
        # cleaned up.  If not used as a context manager, users of this object
        self._cleaned = False

        if dind:
            docker.rm("-f", self.name, _ok_code=[0, 1])
            docker.run("--privileged", "-v", os.getcwd()+":/code", "--name",
                       self.name,
                       "-e", "DOCKER_DAEMON_ARGS="
                       "--kv-store=consul:%s:8500" % utils.get_ip(),
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
            self.ip = get_ip()

        if start_calico:
            self.start_calico_node()
            self.assert_driver_up()

    def execute(self, command):
        """
        Pass a command into a host container.

        Raises a DockerHostExecError() if the command returns a non-zero
        return code.

        :param command:  The command to execute.
        :return: The output from the command with leading and trailing
        whitespace removed.
        """
        etcd_auth = "ETCD_AUTHORITY=%s:2379" % get_ip()
        # Export the environment, in case the command has multiple parts, e.g.
        # use of | or ;
        command = "export %s; %s" % (etcd_auth, command)

        if self.dind:
            command = self.escape_bash_single_quotes(command)
            command = "docker exec -it %s bash -c '%s'" % (self.name,
                                                           command)
        try:
            output = check_output(command, shell=True, stderr=STDOUT)
        except CalledProcessError as e:
            # Wrap the original exception with one that gives a better error
            # message (including command output).
            raise DockerHostExecError(e)
        else:
            return output.strip()

    def calicoctl(self, command):
        """
        Convenience function for abstracting away calling the calicoctl
        command.

        Raises a DockerHostExecError() if the command returns a non-zero
        return code.

        :param command:  The calicoctl command line parms as a single string.
        :return: The output from the command with leading and trailing
        whitespace removed.
        """
        if self.dind:
            calicoctl = "/code/dist/calicoctl %s"
        else:
            calicoctl = "dist/calicoctl %s"
        return self.execute(calicoctl % command)

    def start_calico_node(self):
        """
        Start calico in a container inside a host by calling through to the
        calicoctl node command.
        """
        args = ['node', '--ip=%s' % self.ip]
        try:
            if self.ip6:
                args.append('--ip6=%s' % self.ip6)
        except AttributeError:
            # No ip6 configured
            pass

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
        pass

    def remove_workloads(self):
        """
        Remove all containers running on this host.

        Useful for test shut down to ensure the host is cleaned up.
        :return: None
        """
        for workload in self.workloads:
            try:
                self.execute("docker rm -f %s" % workload.name)
            except CalledProcessError as e:
                # Make best effort attempt to clean containers. Don't fail the
                # test if a container can't be removed.
                pass

    def remove_images(self):
        """
        Remove all images running on this host.

        Useful for test shut down to ensure the host is cleaned up.
        :return: None
        """
        cmd = "docker rmi $(docker images -qa)"
        try:
            self.execute(cmd)
        except CalledProcessError:
            # Best effort only.
            pass

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
        self.remove_workloads()
        # And remove the calico-node
        docker.rm("-f", "calico-node", _ok_code=[0, 1])

        if self.dind:
            # For docker in docker, we need to remove images too.
            self.remove_images()
            # Remove the outer container for DinD.
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
        workload = Workload(self, name, ip=ip, image=image, network=network)
        self.workloads.add(workload)
        return workload

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

    def escape_bash_single_quotes(self, command):
        """
        Escape single quotes in bash string strings.

        Replace ' (single-quote) in the command with an escaped version.
        This needs to be done, since the command is passed to "docker
        exec" to execute and needs to be single quoted.
        Strictly speaking, it's impossible to escape single-quoted
        bash script, but there is a workaround - end the single quoted
         string, then concatenate a double quoted single quote,
        and finally re-open the string with a single quote. Because
        this is inside a single quoted python, string, the single
        quotes also need escaping.

        :param command: The string to escape.
        :return: The escaped string
        """
        return command.replace('\'', '\'"\'"\'')


class DockerHostExecError(CalledProcessError):
    """
    Wrapper for CalledProcessError with an Exception message that gives the
    output captured from the failed command.
    """

    def __init__(self, called_process_error):
        self.called_process_error = called_process_error

    @property
    def returncode(self):
        return self.called_process_error.returncode

    @property
    def output(self):
        return self.called_process_error.output

    @property
    def cmd(self):
        return self.called_process_error.cmd

    def __str__(self):
        return "Command %s failed with RC %s and output:\n%s" % \
               (self.called_process_error.cmd,
                self.called_process_error.returncode,
                self.called_process_error.output)

