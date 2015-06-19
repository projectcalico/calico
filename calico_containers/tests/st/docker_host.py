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
import sh
from sh import docker, ErrorReturnCode
from functools import partial

from utils import get_ip, delete_container, retry_until_success
from workload import Workload


class DockerHost(object):
    """
    A host container which will hold workload containers to be networked by calico.
    """
    def __init__(self, name, start_calico=True, as_num=None):
        """
        Create a container using an image made for docker-in-docker. Load saved
        images into it.
        """
        self.name = name
        self.as_num = None

        pwd = sh.pwd().stdout.rstrip()
        docker.run("--privileged", "-v", pwd+":/code", "--name", self.name, "-tid", "jpetazzo/dind")

        # Since `calicoctl node` doesn't fix ipv6 forwarding and module loading, we must manually fix it
        self.calicoctl("checksystem --fix")

        self.ip = docker.inspect("--format", "{{ .NetworkSettings.IPAddress }}",
                                 self.name).stdout.rstrip()

        self.ip6 = docker.inspect("--format", "{{ .NetworkSettings.GlobalIPv6Address }}",
                             self.name).stdout.rstrip()

        # Make sure docker is up
        docker_ps = partial(self.execute, "docker ps")
        retry_until_success(docker_ps, ex_class=ErrorReturnCode)
        self.execute("docker load --input /code/calico_containers/calico-node.tar")
        self.execute("docker load --input /code/calico_containers/busybox.tar")

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
        """
        Convenience function for abstracting away calling the calicoctl command.
        """
        calicoctl = "/code/dist/calicoctl %s"
        return self.execute(calicoctl % command, **kwargs)

    def start_calico_node(self):
        """
        Start calico in a container inside a host by calling through to the
        calicoctl node command.
        """
        args = ['node', '--ip=%s' % self.ip]
        if self.ip6:
            args.append('--ip6=%s' % self.ip6)
        if self.as_num:
            args.append('--as=%s' % self.as_num)
        cmd = ' '.join(args)
        self.calicoctl(cmd)

    def assert_powerstrip_up(self):
        """
        Check that powerstrip is up by running 'docker ps' through port 2377.
        """
        powerstrip = partial(self.execute, "docker ps", use_powerstrip=True)
        retry_until_success(powerstrip, ex_class=ErrorReturnCode)

    def create_workload(self, name, ip=None, image="busybox", use_powerstrip=True):
        """
        Create a workload container inside this host container.
        """
        return Workload(self, name, ip=ip, image=image, use_powerstrip=use_powerstrip)
