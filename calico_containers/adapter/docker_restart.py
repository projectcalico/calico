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

import os
import time
import sh
import fileinput
import sys

"""
Update docker to use a different unix socket, so powerstrip can run
its proxy on the "normal" one. This provides simple access for
existing tools to the powerstrip proxy.

Set the docker daemon to listen on the docker.real.sock by updating
the config, clearing old sockets and restarting.

Currently "support" upstart (Debian/Ubuntu) and systemd (Redhat/Centos) but
the logic for detecting and modifying config is brittle and lightly tested.
Use with caution...
"""
REAL_SOCK = "/var/run/docker.real.sock"
POWERSTRIP_SOCK = "/var/run/docker.sock"


def _replace_all(filename, search, replace):
    for line in fileinput.input(filename, inplace=1):
        if search in line:
            line = line.replace(search, replace)
        sys.stdout.write(line)


def create_restarter():
    """
    Detect what init system is being used and return the appropriate handler.
    :return: A "restarter" object.
    """
    if os.path.exists(SystemdRestarter.DOCKER_SYSTEMD_SERVICE):
        return SystemdRestarter()
    elif os.path.exists(UpstartRestarter.DOCKER_DEFAULT_FILENAME):
        return UpstartRestarter()
    else:
        return NullRestarter()


class NullRestarter():
    def is_using_alternative_socket(self):
        return False
    def restart_docker_with_alternative_unix_socket(self):
        print "Unsupported"
    def restart_docker_without_alternative_unix_socket(self):
        print "Unsupported"


def _clean_socks():
    if os.path.exists(REAL_SOCK):
        os.remove(REAL_SOCK)
    if os.path.exists(POWERSTRIP_SOCK):
        os.remove(POWERSTRIP_SOCK)


class SystemdRestarter():
    DOCKER_SYSTEMD_SERVICE = "/usr/lib/systemd/system/docker.service"
    SYSTEMD_DEFAULT = "ExecStart=/usr/bin/docker -d $OPTIONS \\"
    SYSTEMD_MODIFIED = "ExecStart=/usr/bin/docker -d $OPTIONS " \
                       "-H unix://%s \\" % REAL_SOCK

    def _clean_restart_docker(self, sock_to_wait_on):
        _clean_socks()
        systemctl = sh.Command._create("systemctl")
        systemctl("daemon-reload")
        systemctl("restart", "docker.service")

        # Wait for docker to create the socket
        while not os.path.exists(sock_to_wait_on):
            time.sleep(0.1)

    def is_using_alternative_socket(self):
        if self.SYSTEMD_MODIFIED in open(self.DOCKER_SYSTEMD_SERVICE).read():
            return True

    def restart_docker_with_alternative_unix_socket(self):
        if not self.is_using_alternative_socket():
            _replace_all(self.DOCKER_SYSTEMD_SERVICE,
                         self.SYSTEMD_DEFAULT,
                         self.SYSTEMD_MODIFIED)
            self._clean_restart_docker(REAL_SOCK)

        # Always remove the socket that powerstrip will use, as it gets upset
        # otherwise.
        if os.path.exists(POWERSTRIP_SOCK):
            os.remove(POWERSTRIP_SOCK)

    def restart_docker_without_alternative_unix_socket(self):
        if self.is_using_alternative_socket():
            _replace_all(self.DOCKER_SYSTEMD_SERVICE,
                         self.SYSTEMD_MODIFIED,
                         self.SYSTEMD_DEFAULT)
            self._clean_restart_docker(POWERSTRIP_SOCK)


class UpstartRestarter():
    DOCKER_DEFAULT_FILENAME = "/etc/default/docker"
    DOCKER_OPTIONS = 'DOCKER_OPTS="-H unix://%s"' % REAL_SOCK

    def _clean_restart_docker(self, sock_to_wait_on):
        _clean_socks()
        restart = sh.Command._create("restart")
        restart("docker")

        # Wait for docker to create the socket
        while not os.path.exists(sock_to_wait_on):
            time.sleep(0.1)

    def is_using_alternative_socket(self):
        if self.DOCKER_OPTIONS in open(self.DOCKER_DEFAULT_FILENAME).read():
            return True

    def restart_docker_with_alternative_unix_socket(self):
        if not self.is_using_alternative_socket():
            with open(self.DOCKER_DEFAULT_FILENAME, "a") as docker_config:
                docker_config.write(self.DOCKER_OPTIONS)
            self._clean_restart_docker(REAL_SOCK)

        # Always remove the socket that powerstrip will use, as it gets upset
        # otherwise.
        if os.path.exists(POWERSTRIP_SOCK):
            os.remove(POWERSTRIP_SOCK)

    def restart_docker_without_alternative_unix_socket(self):
        if self.is_using_alternative_socket():
            good_lines = [line for line in open(
                self.DOCKER_DEFAULT_FILENAME)
                          if self.DOCKER_OPTIONS not in line]
            open(self.DOCKER_DEFAULT_FILENAME, 'w').writelines(good_lines)
            self._clean_restart_docker(POWERSTRIP_SOCK)