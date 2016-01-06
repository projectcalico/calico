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
from nose_parameterized import parameterized

from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Endpoint, Rule, Rules

from calico_cni.policy_drivers import (DefaultPolicyDriver, ApplyProfileError, 
                        KubernetesDefaultPolicyDriver)


class DefaultPolicyDriverTest(unittest.TestCase):
    """
    Test class for DefaultPolicyDriver class.
    """
    def setUp(self):
        self.network_name = "test_net_name"
        self.driver = DefaultPolicyDriver(self.network_name)
        assert_equal(self.driver.profile_name, self.network_name)

        # Mock the DatastoreClient
        self.client = MagicMock(spec=DatastoreClient)
        self.driver._client = self.client

    def test_apply_new_profile(self):
        # Mock.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.profile_ids = []
        endpoint.endpoint_id = "12345"
        self.client.profile_exists.return_value = False

        # Call
        self.driver.apply_profile(endpoint)

        # Assert
        self.client.append_profiles_to_endpoint.assert_called_once_with(
                profile_names=[self.network_name], endpoint_id="12345"
        )

    def test_apply_same_profile(self):
        # Mock.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.profile_ids = [self.network_name]
        endpoint.endpoint_id = "12345"
        self.client.profile_exists.return_value = False

        # Call
        self.driver.apply_profile(endpoint)

        # Assert
        assert_false(self.client.append_profiles_to_endpoint.called)

    def test_apply_profile_error(self):
        # Mock.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.profile_ids = []
        endpoint.endpoint_id = "12345"
        endpoint.name = "cali12345"
        self.client.profile_exists.return_value = False
        self.client.append_profiles_to_endpoint.side_effect = KeyError

        # Call
        assert_raises(ApplyProfileError, self.driver.apply_profile, endpoint)

    def test_remove_profile(self):
        # Should do nothing.
        self.driver.remove_profile()

    @parameterized.expand([
        ("invalid=name"), ("^regex$"),
    ])
    def test_invalid_network_name(self, net_name):
        assert_raises(ValueError, DefaultPolicyDriver, net_name)


class KubernetesDefaultPolicyDriverTest(unittest.TestCase):
    """
    Test class for KubernetesDefaultPolicyDriver class.
    """
    def setUp(self):
        self.network_name = "test_net_name"
        self.driver = KubernetesDefaultPolicyDriver(self.network_name)
        assert_equal(self.driver.profile_name, self.network_name)

        # Mock the DatastoreClient
        self.client = MagicMock(spec=DatastoreClient)
        self.driver._client = self.client

    def test_generate_rules(self):
        # Generate rules
        rules = self.driver.generate_rules()

        # Assert correct.
        expected = Rules(id=self.network_name,
                         inbound_rules=[Rule(action="allow")],
                         outbound_rules=[Rule(action="allow")])
        assert_equal(rules, expected)
