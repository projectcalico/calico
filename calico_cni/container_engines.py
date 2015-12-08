# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
from util import configure_logging

from docker import Client
from docker.errors import APIError

# Docker config.
DOCKER_HOST_ENV = "DOCKER_HOST"
DOCKER_SOCKET = "unix://var/run/docker.sock"
DOCKER_VERSION = "1.16"


LOG_FILENAME = "cni.log"
_log = logging.getLogger(__name__)
configure_logging(_log, LOG_FILENAME)


class BaseContainerEngine(object):
    """
    Abstract base class for interacting with containerizers.
    """
    def uses_host_networking(self, container_id):
        """
        Whether or not this container is networking using host 
        networking.
        """
        raise NotImplementedError()

class DefaultEngine(BaseContainerEngine):
    """
    Implements default container engine for a generic CNI plugin.
    """
    def uses_host_networking(self, container_id): 
        """
        Rkt does not call CNI plugins when --net=host is set.
        """
        return False

class DockerEngine(BaseContainerEngine):
    """
    Implemented container engine for Docker.
    """
    def __init__(self):
        BaseContainerEngine.__init__(self)
        self._client = Client(version=DOCKER_VERSION,
                    base_url=os.getenv(DOCKER_HOST_ENV, DOCKER_SOCKET))

    def uses_host_networking(self, container_id):
        """
        Use docker inspect to determine if this container has been 
        configured with NetworkMode == host.

        Throws a KeyError if the container cannot be inspected.
        """
        _log.debug("Using Docker inspect")
        info = self._docker_inspect(container_id)
        _log.debug("Got container info: %s", info)
        return info["HostConfig"]["NetworkMode"] == "host"

    def _docker_inspect(self, container_id):
        """
        Calls docker inspect on the given container_id and returns the output. 
        Throws a KeyError if the container cannot be inspected.
        """
        try:
            info = self._client.inspect_container(container_id)
        except APIError, e:
            if e.response.status_code == 404:
                _log.error("Container `%s` was not found.", container_id)
            else:
                _log.error(e.message)
            raise KeyError("Unable to inspect container.")
        return info
