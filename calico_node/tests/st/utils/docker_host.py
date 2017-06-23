# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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
import json
import os
import re
import uuid
import yaml
from functools import partial
from subprocess import CalledProcessError, Popen, PIPE

from log_analyzer import LogAnalyzer, FELIX_LOG_FORMAT, TIMESTAMP_FORMAT
from network import DockerNetwork
from tests.st.utils.constants import DEFAULT_IPV4_POOL_CIDR
from tests.st.utils.exceptions import CommandExecError
from utils import get_ip, log_and_run, retry_until_success, ETCD_SCHEME, \
    ETCD_CA, ETCD_KEY, ETCD_CERT, ETCD_HOSTNAME_SSL
from workload import Workload

logger = logging.getLogger(__name__)
# We want to default CHECKOUT_DIR if either the ENV var is unset
# OR its set to an empty string.
CHECKOUT_DIR = os.getenv("HOST_CHECKOUT_DIR", "")
if CHECKOUT_DIR == "":
    CHECKOUT_DIR = os.getcwd()

NODE_CONTAINER_NAME = os.getenv("NODE_CONTAINER_NAME", "calico/node:latest")

if ETCD_SCHEME == "https":
    CLUSTER_STORE_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " \
                                "--cluster-store-opt kv.cacertfile=%s " \
                                "--cluster-store-opt kv.certfile=%s " \
                                "--cluster-store-opt kv.keyfile=%s " % \
                                (ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                 ETCD_KEY)
else:
    CLUSTER_STORE_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " % \
                                get_ip()

class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by
    Calico.

    :param calico_node_autodetect_ip: When set to True, the test framework
    will not perform IP detection, and will run `calicoctl node` without
    explicitly passing in a value for --ip. This means calico-node will be
    forced to do its IP detection.
    :param override_hostname: When set to True, the test framework will
    choose an alternate hostname for the host which it will pass to all
    calicoctl components as the HOSTNAME environment variable.  If set
    to False, the HOSTNAME environment is not explicitly set.
    """

    # A static list of Docker networks that are created by the tests.  This
    # list covers all Docker hosts.
    docker_networks = []

    def __init__(self, name, start_calico=True, dind=True,
                 additional_docker_options="",
                 post_docker_commands=["docker load -i /code/calico-node.tar",
                                       "docker load -i /code/busybox.tar"],
                 calico_node_autodetect_ip=False,
                 simulate_gce_routing=False,
                 override_hostname=False):
        self.name = name
        self.dind = dind
        self.workloads = set()
        self.ip = None
        self.log_analyzer = None
        """
        An IP address value to pass to calicoctl as `--ip`. If left as None,
        no value will be passed, forcing calicoctl to do auto-detection.
        """

        self.ip6 = None
        """
        An IPv6 address value to pass to calicoctl as `--ipv6`. If left as
        None, no value will be passed.
        """

        self.override_hostname = None if not override_hostname else \
            uuid.uuid1().hex[:16]
        """
        Create an arbitrary hostname if we want to override.
        """

        # This variable is used to assert on destruction that this object was
        # cleaned up.  If not used as a context manager, users of this object
        # must invoke cleanup.
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
            # Set iptables=false to prevent iptables error when using dind
            # libnetwork
            log_and_run("docker run %s "
                        "calico/dind:latest "
                        "--iptables=false "
                        "%s" %
                        (docker_args, additional_docker_options))

            self.ip = log_and_run(
                "docker inspect --format "
                "'{{.NetworkSettings.Networks.bridge.IPAddress}}' %s" %
                self.name)

            # Make sure docker is up
            docker_ps = partial(self.execute, "docker ps")
            retry_until_success(docker_ps, ex_class=CalledProcessError,
                                retries=10)

            if simulate_gce_routing:
                # Simulate addressing and routing setup as on a GCE instance:
                # the instance has a /32 address (which means that it appears
                # not to be directly connected to anything) and a default route
                # that does not have the 'onlink' flag to override that.
                #
                # First check that we can ping the Docker bridge, and trace out
                # initial state.
                self.execute("ping -c 1 -W 2 172.17.0.1")
                self.execute("ip a")
                self.execute("ip r")

                # Change the normal /16 IP address to /32.
                self.execute("ip a del %s/16 dev eth0" % self.ip)
                self.execute("ip a add %s/32 dev eth0" % self.ip)

                # Add a default route via the Docker bridge.
                self.execute("ip r a 172.17.0.1 dev eth0")
                self.execute("ip r a default via 172.17.0.1 dev eth0")

                # Trace out final state, and check that we can still ping the
                # Docker bridge.
                self.execute("ip a")
                self.execute("ip r")
                self.execute("ping -c 1 -W 2 172.17.0.1")

            for command in post_docker_commands:
                self.execute(command)
        elif not calico_node_autodetect_ip:
            # Find the IP so it can be specified as `--ip` when launching
            # node later.
            self.ip = get_ip(v6=False)
            self.ip6 = get_ip(v6=True)

        if start_calico:
            self.start_calico_node()

    def execute(self, command, raise_exception_on_failure=True):
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

        return log_and_run(command, raise_exception_on_failure=raise_exception_on_failure)

    def execute_readline(self, command):
        """
        Execute a command and return individual lines as a generator.
        Raises an exception if the return code is non-zero.  Stderr is ignored.

        Use this rather than execute if the command outputs a large amount of
        data that cannot be handled as a single string.

        :return: Generator of individual lines.
        """
        logger.debug("Running command on %s", self.name)
        logger.debug("  - Command: %s", command)
        if self.dind:
            command = self.escape_shell_single_quotes(command)
            command = "docker exec -it %s sh -c '%s'" % (self.name,
                                                         command)
        logger.debug("Final command: %s", command)
        proc = Popen(command, stdout=PIPE, shell=True)

        try:
            # Read and return one line at a time until no more data is
            # returned.
            for line in proc.stdout:
                yield line
        finally:
            status = proc.wait()
            logger.debug("- return: %s", status)

        if status:
            raise Exception("Command %s returned non-zero exit code %s" %
                            (command, status))

    def calicoctl(self, command, version=None):
        """
        Convenience function for abstracting away calling the calicoctl
        command.

        Raises a CommandExecError() if the command returns a non-zero
        return code.

        :param command:  The calicoctl command line parms as a single string.
        :param version:  The calicoctl version to use (this is appended to the
                         executable name.  It is assumed the Makefile will ensure
                         the required versions are downloaded.
        :return: The output from the command with leading and trailing
        whitespace removed.
        """
        if not version:
            calicoctl = os.environ.get("CALICOCTL", "/code/dist/calicoctl")
        else:
            calicoctl = "/code/dist/calicoctl-" + version

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
        # If the hostname is being overriden, then export the HOSTNAME
        # environment.
        if self.override_hostname:
            calicoctl = "export HOSTNAME=%s; %s" % (
                self.override_hostname, calicoctl)

        return self.execute(calicoctl + " " + command)

    def start_calico_node(self, options="", with_ipv4pool_cidr_env_var=True):
        """
        Start calico in a container inside a host by calling through to the
        calicoctl node command.
        """
        args = ['node', 'run']
        if with_ipv4pool_cidr_env_var:
            args.append('--dryrun')
        if "--node-image" not in options:
            args.append('--node-image=%s' % NODE_CONTAINER_NAME)

        # Add the IP addresses if required and we aren't explicitly specifying
        # them in the options.  The --ip and  --ip6 options can be specified
        # using "=" or space-separated parms.
        if self.ip and "--ip=" not in options and "--ip " not in options:
            args.append('--ip=%s' % self.ip)
        if self.ip6 and "--ip6=" not in options and "--ip6 " not in options:
            args.append('--ip6=%s' % self.ip6)
        args.append(options)

        cmd = ' '.join(args)

        if with_ipv4pool_cidr_env_var:
            # Run the dryrun command, then modify and execute the command that
            # that tells us.
            assert "--dryrun" in cmd
            output = self.calicoctl(cmd)

            # Look for the line in the output that includes "docker run",
            # "--net=host" and "--name=calico-node".
            for line in output.split('\n'):
                if re.match(r'docker run .*--net=host .*--name=calico-node', line):
                    # This is the line we want to modify.
                    break
            else:
                raise AssertionError("No node run line in %s" % output)

            # Break the line at the first occurrence of " -e ".
            prefix, _, suffix = line.rstrip().partition(" -e ")

            # Construct the calicoctl command that we want, including the
            # CALICO_IPV4POOL_CIDR setting.
            modified_cmd = (
                prefix +
                " -e CALICO_IPV4POOL_CIDR=%s -e " % DEFAULT_IPV4_POOL_CIDR +
                suffix
            )

            # Now run that.
            self.execute(modified_cmd)
        else:
            # Run the non-dryrun calicoctl node run command.
            self.calicoctl(cmd)

        self.attach_log_analyzer()

    def set_ipip_enabled(self, enabled):
        pools_output = self.calicoctl("get ippool -o yaml")
        pools_dict = yaml.safe_load(pools_output)
        for pool in pools_dict:
            print "Pool is %s" % pool
            if ':' not in pool['metadata']['cidr']:
                pool['spec']['ipip'] = {'mode': 'always', 'enabled': enabled}
            self.writefile("ippools.yaml", pools_dict)
            self.calicoctl("apply -f ippools.yaml")

    def attach_log_analyzer(self):
        self.log_analyzer = LogAnalyzer(self,
                                        "/var/log/calico/felix/current",
                                        FELIX_LOG_FORMAT,
                                        TIMESTAMP_FORMAT)

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

        # If the hostname has been overridden on this host, then pass it in
        # as an environment variable.
        if self.override_hostname:
            hostname_args = "-e HOSTNAME=%s" % self.override_hostname
        else:
            hostname_args = ""

        self.execute("docker run -d --net=host --privileged "
                     "--name=calico-node "
                     "%s "
                     "-e IP=%s "
                     "-e ETCD_AUTHORITY=%s -e ETCD_SCHEME=%s %s "
                     "-v /var/log/calico:/var/log/calico "
                     "-v /var/run/calico:/var/run/calico "
                     "%s" % (hostname_args, self.ip, etcd_auth, ETCD_SCHEME,
                             ssl_args, NODE_CONTAINER_NAME)
                     )

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
        self.cleanup(log_extra_diags=bool(exc_type))

    def cleanup(self, log_extra_diags=False):
        """
        Clean up this host, including removing any containers created.  This is
        necessary especially for Docker-in-Docker so we don't leave dangling
        volumes.

        Also, perform log analysis to check for any errors, raising an exception
        if any were found.

        If log_extra_is set to True we will log some extra diagnostics (this is
        set to True if the DockerHost context manager exits with an exception).
        Extra logs will also be output if the log analyzer detects any errors.
        """
        # Check for logs before tearing down, log extra diags if we spot an error.
        log_exception = None
        try:
            if self.log_analyzer is not None:
                self.log_analyzer.check_logs_for_exceptions()
        except Exception, e:
            log_exception = e
            log_extra_diags = True

        # Log extra diags if we need to.
        if log_extra_diags:
            self.log_extra_diags()

        logger.info("# Cleaning up host %s", self.name)
        if self.dind:
            # For Docker-in-Docker, we need to remove all containers and
            # all images.
            # Start by just removing the workloads and then attempt cleanup of
            # networks...
            self.remove_workloads()
            self.cleanup_networks()

            # ...delete any remaining containers and the images...
            self.remove_containers()
            self.remove_images()

            # ...and the outer container for DinD.
            log_and_run("docker rm -f %s || true" % self.name)
        else:
            # For non Docker-in-Docker, we can only remove the containers we
            # created - so remove the workloads, attempt cleanup of networks
            # and delete the calico node.
            self.remove_workloads()
            self.cleanup_networks()
            log_and_run("docker rm -f calico-node || true")

        self._cleaned = True

        # Now that tidy-up is complete, re-raise any exceptions found in the logs.
        if log_exception:
            raise log_exception

    def cleanup_networks(self):
        """
        Attempt to cleanup any networks that are stored globally.  Note that
        Docker will not allow a network to be deleted whilst there are
        endpoints associated with the network - thus any networks that could
        not be deleted are added back to the global list and will be removed
        via another docker host cleanup (after removing its endpoints).
        """
        q_networks = []
        while self.docker_networks:
            nw = self.docker_networks.pop()
            try:
                nw.delete(host=self)
            except CommandExecError:
                q_networks.append(nw)
        self.docker_networks.extend(q_networks)

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

    def create_workload(self, name, image="busybox", network="bridge", ip=None, labels=[]):
        """
        Create a workload container inside this host container.
        """
        workload = Workload(self, name, image=image, network=network, ip=ip, labels=labels)
        self.workloads.add(workload)
        return workload

    def create_network(self, name, driver="calico", ipam_driver="calico-ipam",
                       subnet=None):
        """
        Create a Docker network using this host.  If the DockerHost is used
        as a context manager, exit processing will attempt deletion of *all*
        networks created across *all* Docker hosts - if you do not want the
        tidy up of networks to occur automatically, don't use the DockerHost as
        a context manager and perform tidy explicitly.

        :param name: The name of the network.  This must be unique per cluster
        and it is the user-facing identifier for the network.
        :param driver: The name of the network driver to use.  (The Calico
        driver is the default.)
        :param ipam_driver:  The name of the IPAM driver to use.  (The Calico
        driver is the default.)
        :param subnet: The subnet IP pool to assign IPs from.
        :return: A DockerNetwork object.
        """
        nw = DockerNetwork(self, name, driver=driver, ipam_driver=ipam_driver,
                           subnet=subnet)

        # Store the network so that we can attempt to remove it when this host
        # or another host exits.
        self.docker_networks.append(nw)
        return nw

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

        :return: hostname of DockerHost
        """
        # If overriding the hostname, return that one.
        if self.override_hostname:
            return self.override_hostname

        command = "docker inspect --format {{.Config.Hostname}} %s" % self.name
        return log_and_run(command)

    def writefile(self, filename, data):
        """
        Writes a file on a host (e.g. a yaml file for loading into calicoctl).
        :param filename: string, the filename to create
        :param data: string, the data to put inthe file
        :return: Return code of execute operation.
        """
        return self.execute("cat << EOF > %s\n%s" % (filename, data))

    def writejson(self, filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        text = json.dumps(data,
                          sort_keys=True,
                          indent=2,
                          separators=(',', ': '))
        self.writefile(filename, text)

    def add_resource(self, resource_data):
        """
        Add resource specified in resource_data object.
        :param resource_data: object representing json data for the resource
        to add
        """
        self._apply_resources(resource_data)

    def delete_all_resource(self, resource):
        """
        Delete all resources of the specified type.
        :param resource: string, resource type to delete
        """
        # Grab all objects of a resource type
        objects = yaml.load(self.calicoctl("get %s -o yaml" % resource))
        # and delete them (if there are any)
        if len(objects) > 0:
            self._delete_data(objects)

    def _delete_data(self, data):
        logger.debug("Deleting data with calicoctl: %s", data)
        self._exec_calicoctl("delete", data)

    def _apply_resources(self, resources):
        self._exec_calicoctl("apply", resources)

    def _exec_calicoctl(self, action, data):
        # use calicoctl with data
        self.writejson("new_data", data)
        self.calicoctl("%s -f new_data" % action)

    def log_extra_diags(self):
        # Run a set of commands to trace ip routes, iptables and ipsets.
        self.execute("ip route", raise_exception_on_failure=False)
        self.execute("iptables-save", raise_exception_on_failure=False)
        self.execute("ip6tables-save", raise_exception_on_failure=False)
        self.execute("ipset save", raise_exception_on_failure=False)
