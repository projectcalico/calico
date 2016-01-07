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

import unittest
from mock import patch, MagicMock, Mock, call, ANY
from nose.tools import assert_equal, assert_true, assert_false, assert_raises

from docker import Client
from docker.errors import APIError

from calico_cni.container_engines import DockerEngine, DefaultEngine, BaseContainerEngine 


class BaseEngineTest(unittest.TestCase):
    def setUp(self):
        """
        Per-test setup method.
        """
        self.engine = BaseContainerEngine()
        self.engine._client = MagicMock(spec=Client)

    def test_not_implemented(self):
        assert_raises(NotImplementedError, self.engine.uses_host_networking, "1234")


class DockerEngineTest(unittest.TestCase):
    def setUp(self):
        """
        Per-test setup method.
        """
        self.engine = DockerEngine()
        self.engine._client = MagicMock(spec=Client)

    def test_uses_host_networking(self):
        # Mock inspect.
        inspect_result = {"HostConfig": {"NetworkMode": "host"}}
        self.engine._docker_inspect = MagicMock(spec=self.engine._docker_inspect)
        self.engine._docker_inspect.return_value = inspect_result
        container_id = "12345"

        # Call
        result = self.engine.uses_host_networking(container_id)

        # Assert
        assert_true(result)

    def test__docker_inspect(self):
        # Mock
        container_id = "12345"
        info = "some info"
        self.engine._client.inspect_container.return_value = info

        # Call
        result = self.engine._docker_inspect(container_id)

        # Assert
        assert_equal(result, info)

    def test__docker_inspect_error(self):
        # Mock
        container_id = "12345"
        response = MagicMock()
        response.status_code = 300 
        explanation = "explanation"
        msg = "message"
        self.engine._client.inspect_container.side_effect = APIError(msg, response, explanation) 

        # Call
        assert_raises(KeyError, self.engine._docker_inspect, container_id)

    def test__docker_inspect_error_not_found(self):
        # Mock
        container_id = "12345"
        response = MagicMock()
        response.status_code = 404 
        explanation = "explanation"
        self.engine._client.inspect_container.side_effect = APIError(1, response, explanation) 

        # Call
        assert_raises(KeyError, self.engine._docker_inspect, container_id)
