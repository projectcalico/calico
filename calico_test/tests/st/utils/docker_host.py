# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import os
from subprocess import CalledProcessError
from functools import partial

from utils import get_ip, log_and_run, retry_until_success, ETCD_SCHEME, \
                  ETCD_CA, ETCD_KEY, ETCD_CERT, ETCD_HOSTNAME_SSL
from workload import Workload
from network import DockerNetwork

logger = logging.getLogger(__name__)
CHECKOUT_DIR = os.getenv("HOST_CHECKOUT_DIR", os.getcwd())

class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by
    Calico.

    :param calico_node_autodetect_ip: When set to True, the test framework
    will not perform IP detection, and will run `calicoctl node` without explicitly
    passing in a value for --ip. This means calico-node will be forced to do its IP detection.
    """
    def __init__(self, name, start_calico=True, dind=True,
                 additional_docker_options="",
                 post_docker_commands=["docker load -i /code/calico-node.tar",
                                       "docker load -i /code/busybox.tar"],
                 calico_node_autodetect_ip=False):
        self.name = name
        self.dind = dind
        self.workloads = set()
        self.ip = None
        """
        An IP address value to pass to calicoctl as `--ip`. If left as None, no value will be passed,
        forcing calicoctl to do auto-detection.
        """

        self.ip6 = None
        """
        An IPv6 address value to pass to calicoctl as `--ipv6`. If left as None, no value will be passed.
        """

        # This variable is used to assert on destruction that this object was
        # cleaned up.  If not used as a context manager, users of this object
        self._cleaned = False

        docker_args = "--privileged -tid " \
                      "-v /lib/modules:/lib/modules " \
                      "-v %s/certs:%s/certs -v %s:/code --name %s" % \
                      (CHECKOUT_DIR, CHECKOUT_DIR, CHECKOUT_DIR,
                       self.name)
        if ETCD_SCHEME == "https":
            docker_args += " --add-host %s:%s" % (ETCD_HOSTNAME_SSL, get_ip())

        if dind:
            log_and_run("docker rm -f %s || true" % self.name)
            # Pass the certs directory as a volume since the etcd SSL/TLS
            # environment variables use the full path on the host.
            # Set iptables=false to prevent iptables error when using dind libnetwork
            log_and_run("docker run %s "
                        "calico/dind:latest "
                        " --storage-driver=aufs "
                        "--iptables=false "
                        "%s" %
                    (docker_args, additional_docker_options))

            self.ip = log_and_run("docker inspect --format "
                              "'{{.NetworkSettings.Networks.bridge.IPAddress}}' %s" % self.name)

            # Make sure docker is up
            docker_ps = partial(self.execute, "docker ps")
            retry_until_success(docker_ps, ex_class=CalledProcessError,
                                retries=10)
            for command in post_docker_commands:
                self.execute(command)
        elif not calico_node_autodetect_ip:
            # Find the IP so it can be specified as `--ip` when launching node later.
            self.ip = get_ip(v6=False)
            self.ip6 = get_ip(v6=True)

        if start_calico:
            self.start_calico_node()

    def execute(self, command):
        """
        Pass a command into a host container.

        Raises a CommandExecError() if the command returns a non-zero
        return code.

        :param command:  The command to execute.
        :return: The output from the command with leading and trailing
        whitespace removed.
        """
        if self.dind:
            command = self.escape_shell_single_quotes(command)
            command = "docker exec -it %s sh -c '%s'" % (self.name,
                                                         command)

        return log_and_run(command)


    def calicoctl(self, command):
        """
        Convenience function for abstracting away calling the calicoctl
        command.

        Raises a CommandExecError() if the command returns a non-zero
        return code.

        :param command:  The calicoctl command line parms as a single string.
        :return: The output from the command with leading and trailing
        whitespace removed.
        """
        calicoctl = os.environ.get("CALICOCTL", "/code/dist/calicoctl")

        if ETCD_SCHEME == "https":
            etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
        else:
            etcd_auth = "%s:2379" % get_ip()
        # Export the environment, in case the command has multiple parts, e.g.
        # use of | or ;
        #
        # Pass in all etcd params, the values will be empty if not set anyway
        calicoctl = "export ETCD_AUTHORITY=%s; " \
                    "export ETCD_SCHEME=%s; " \
                    "export ETCD_CA_CERT_FILE=%s; " \
                    "export ETCD_CERT_FILE=%s; " \
                    "export ETCD_KEY_FILE=%s; %s" % \
                    (etcd_auth, ETCD_SCHEME, ETCD_CA, ETCD_CERT, ETCD_KEY,
                     calicoctl)
        return self.execute(calicoctl + " " + command)

    def start_calico_node(self, options=""):
        """
        Start calico in a container inside a host by calling through to the
        calicoctl node command.

        :param as_num: The AS Number for this node.  A value of None uses the
        inherited default value.
        """
        args = ['node']
        if self.ip:
            args.append('--ip=%s' % self.ip)
        if self.ip6:
            args.append('--ip6=%s' % self.ip6)
        args.append(options)

        cmd = ' '.join(args)
        self.calicoctl(cmd)

    def start_calico_node_with_docker(self):
        """
        Start calico in a container inside a host by calling docker directly.
        """
        if ETCD_SCHEME == "https":
            etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
            ssl_args = "-e ETCD_CA_CERT_FILE=%s " \
                       "-e ETCD_CERT_FILE=%s " \
                       "-e ETCD_KEY_FILE=%s " \
                       "-v %s/certs:%s/certs " \
                       % (ETCD_CA, ETCD_CERT, ETCD_KEY,
                          CHECKOUT_DIR, CHECKOUT_DIR)

        else:
            etcd_auth = "%s:2379" % get_ip()
            ssl_args = ""

        self.execute("docker run -d --net=host --privileged "
                     "--name=calico-node "
                     "-e IP=%s -e ETCD_AUTHORITY=%s "
                     "-e ETCD_SCHEME=%s %s "
                     "-v /var/log/calico:/var/log/calico "
                     "-v /var/run/calico:/var/run/calico "
                     "calico/node:latest" % (self.ip, etcd_auth,
                                             ETCD_SCHEME, ssl_args))


    def remove_workloads(self):
        """
        Remove all containers running on this host.

        Useful for test shut down to ensure the host is cleaned up.
        :return: None
        """
        for workload in self.workloads:
            try:
                self.execute("docker rm -f %s" % workload.name)
            except CalledProcessError:
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

    def remove_containers(self):
        """
        Remove all containers running on this host.

        Useful for test shut down to ensure the host is cleaned up.
        :return: None
        """
        cmd = "docker rm -f $(docker ps -qa)"
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
        Clean up this host, including removing any containers created.  This is
        necessary especially for Docker-in-Docker so we don't leave dangling
        volumes.
        :return:
        """
        logger.info("# Cleaning up host %s", self.name)
        if self.dind:
            # For Docker-in-Docker, we need to remove all containers and
            # all images...
            self.remove_containers()
            self.remove_images()

            # ...and the outer container for DinD.
            log_and_run("docker rm -f %s || true" % self.name)
        else:
            # For non Docker-in-Docker, we can only remove the containers we
            # created - so remove the workloads and the calico node.
            self.remove_workloads()
            log_and_run("docker rm -f calico-node || true")

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

    def create_workload(self, name, image="busybox", network="bridge", ip=None):
        """
        Create a workload container inside this host container.
        """
        workload = Workload(self, name, image=image, network=network, ip=ip)
        self.workloads.add(workload)
        return workload

    def create_network(self, name, driver="calico", ipam_driver=None,
                       subnet=None):
        """
        Create a Docker network using this host.

        :param name: The name of the network.  This must be unique per cluster
        and it the user-facing identifier for the network.  (Calico itself will
        get a UUID for the network via the driver API and will not get the
        name).
        :param driver: The name of the network driver to use.  (The Calico
        driver is the default.)
        :param ipam_driver:  The name of the IPAM driver to use, or None to use
        the default driver.
        :param subnet: The subnet IP pool to assign IPs from.
        :return: A DockerNetwork object.
        """
        return DockerNetwork(self, name, driver=driver, ipam_driver=ipam_driver,
                             subnet=subnet)

    @staticmethod
    def escape_shell_single_quotes(command):
        """
        Escape single quotes in shell strings.

        Replace ' (single-quote) in the command with an escaped version.
        This needs to be done, since the command is passed to "docker
        exec" to execute and needs to be single quoted.
        Strictly speaking, it's impossible to escape single-quoted
        shell script, but there is a workaround - end the single quoted
         string, then concatenate a double quoted single quote,
        and finally re-open the string with a single quote. Because
        this is inside a single quoted python, string, the single
        quotes also need escaping.

        :param command: The string to escape.
        :return: The escaped string
        """
        return command.replace('\'', '\'"\'"\'')

    def get_hostname(self):
        """
        Get the hostname from Docker
        The hostname is a randomly generated string.
        Note, this function only works with a host with dind enabled.
        Raises an exception if dind is not enabled.

        :param host: DockerHost object
        :return: hostname of DockerHost
        """
        command = "docker inspect --format {{.Config.Hostname}} %s" % self.name
        return log_and_run(command)
