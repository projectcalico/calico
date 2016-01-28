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

from calico_cni.container_engines import DockerEngine, DefaultEngine, get_container_engine


class DockerEngineTest(unittest.TestCase):
    def setUp(self):
        """
        Per-test setup method.
        """
        self.engine = DockerEngine()

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

    @patch("calico_cni.container_engines.Client", autospec=True)
    def test__docker_inspect(self, m_client):
        # Mock
        container_id = "12345"
        info = "some info"
        m_client().inspect_container.return_value = info

        # Call
        result = self.engine._docker_inspect(container_id)

        # Assert
        assert_equal(result, info)

    @patch("calico_cni.container_engines.Client", autospec=True)
    def test__docker_inspect_error(self, m_client):
        # Mock
        container_id = "12345"
        response = MagicMock()
        response.status_code = 300 
        explanation = "explanation"
        msg = "message"
        m_client().inspect_container.side_effect = APIError(msg, response, explanation) 

        # Call
        assert_raises(KeyError, self.engine._docker_inspect, container_id)

    @patch("calico_cni.container_engines.Client", autospec=True)
    def test__docker_inspect_error_not_found(self, m_client):
        # Mock
        container_id = "12345"
        response = MagicMock()
        response.status_code = 404 
        explanation = "explanation"
        m_client().inspect_container.side_effect = APIError(1, response, explanation) 

        # Call
        assert_raises(KeyError, self.engine._docker_inspect, container_id)

    def test_get_container_engine_docker(self):
        eng = get_container_engine(True)
        assert_true(isinstance(eng, DockerEngine))
