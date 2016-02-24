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

logger = logging.getLogger(__name__)

class DockerNetwork(object):
    """
    A Docker network created by libnetwork.

    Docker networks provide mutual connectivity to the endpoints attached to
    them (and endpoints join/leave sandboxes which are network namespaces used
    by containers).
    """

    def __init__(self, host, name, driver="calico", ipam_driver=None,
                 subnet=None):
        """
        Create the network.
        :param host: The Docker Host which creates the network (note that
        networks
        :param name: The name of the network.  This must be unique per cluster
        and is the user-facing identifier for the network.  (Calico itself will
        get a UUID for the network via the driver API and will not get the
        name).
        :param driver: The name of the network driver to use.  (The Calico
        driver is the default.)
        :param ipam_driver:  The name of the IPAM driver to use, or None to use
        the default driver.
        :param subnet: The subnet IP pool to assign IPs from.
        :return: A DockerNetwork object.
        """
        self.name = name
        self.driver = driver

        self.init_host = host
        """The host which created the network."""

        ipam_option = ("--ipam-driver %s" % ipam_driver) if ipam_driver else ""
        subnet_option = ("--subnet %s" % subnet) if subnet else ""

        cmd = "docker network create -d %s %s %s %s" % \
              (driver, ipam_option, subnet_option, name)
        self.uuid = host.execute(cmd)

    def delete(self):
        """
        Delete the network.
        :return: Nothing
        """
        self.init_host.execute("docker network rm " + self.name)

    def disconnect(self, host, container):
        """
        Disconnect container from network
        :return: Nothing
        """
        host.execute("docker network disconnect %s %s" %
                     (self.name, str(container)))

    def __str__(self):
        return self.name



