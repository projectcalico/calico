# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
from functools import partial
from tests.st.utils.exceptions import CommandExecError
from tests.st.utils.utils import retry_until_success

logger = logging.getLogger(__name__)

global_networking = None
NETWORKING_CNI = "cni"
NETWORKING_LIBNETWORK = "libnetwork"


def global_setting():
    global global_networking
    if global_networking is None:
        global_networking = os.getenv("ST_NETWORKING")
        if global_networking:
            assert global_networking in [NETWORKING_CNI, NETWORKING_LIBNETWORK]
        else:
            global_networking = NETWORKING_CNI
    return global_networking


class DockerNetwork(object):
    """
    A Docker network created by libnetwork.

    Docker networks provide mutual connectivity to the endpoints attached to
    them (and endpoints join/leave sandboxes which are network namespaces used
    by containers).
    """

    def __init__(self, host, name, driver="calico", ipam_driver="calico-ipam",
                 subnet=None):
        """
        Create the network.
        :param host: The Docker Host which creates the network
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
        self.deleted = False

        self.init_host = host
        """The host which created the network."""

        driver_option = ("--driver %s" % driver) if driver else ""
        ipam_option = ("--ipam-driver %s" % ipam_driver) if ipam_driver else ""
        subnet_option = ("--subnet %s" % subnet) if subnet else ""

        # Check if network is present before we create it
        try:
            host.execute("docker network inspect %s" % name)
            # Network exists - delete it
            host.execute("docker network rm " + name)
        except CommandExecError:
            # Network didn't exist, no problem.
            pass

        # Create the network,
        #cmd = "docker network create %s %s %s %s" % \
        #      (driver_option, ipam_option, subnet_option, name)
        #docker_net_create = partial(host.execute, cmd)
        #self.uuid = retry_until_success(docker_net_create)

    def delete(self, host=None):
        """
        Delete the network.
        :param host: The Docker Host to use when deleting the network.  If
        not specified, defaults to the host used to create the network.
        :return: Nothing
        """
        if not self.deleted:
            host = host or self.init_host
        #    host.execute("docker network rm " + self.name)
            self.deleted = True

    def disconnect(self, host, container):
        """
        Disconnect container from network.
        :return: Nothing
        """
        #host.execute("docker network disconnect %s %s" %
        #             (self.name, str(container)))

    def __str__(self):
        return self.name
