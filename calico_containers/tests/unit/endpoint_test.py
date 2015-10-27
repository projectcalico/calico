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

import unittest

from mock import patch
from nose_parameterized import parameterized, param
from calico_ctl import endpoint


class TestEndpoint(unittest.TestCase):

    @parameterized.expand([
        ({'<PROFILES>':['profile-1', 'profile-2', 'profile-3']}, False),
        ({'<PROFILES>':['Profile1', 'Profile!']}, True),
        ({}, False)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl endpoint command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            endpoint.validate_arguments(case)

            # Assert method exits if bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)

    @parameterized.expand([param(['profile-1', 'profile-2', 'profile-3']),
                           param(['Profile1', 'Profile!']),
                           param([])
    ])
    def test_endpoint_profile_set(self, profiles):
        """
        Test setting profiles on an endpoint calls correct functions
        """
        with patch("calico_ctl.endpoint.client", autospec=True) as m_client:
            hostname = "m_hostname"
            orchestrator_id = "m_orchestrator_id"
            workload_id = "m_workload_id"
            endpoint_id = "m_endpoint_id"

            endpoint.endpoint_profile_set(hostname,
                                          orchestrator_id,
                                          workload_id,
                                          endpoint_id,
                                          profiles)

            m_client.set_profiles_on_endpoint.assert_called_once_with(
                                               profiles,
                                               hostname=hostname,
                                               orchestrator_id=orchestrator_id,
                                               workload_id=workload_id,
                                               endpoint_id=endpoint_id)

    @parameterized.expand([
        (['profile-1', 'profile-2', 'profile-3'], True),
        (['test_prof'], True),
        ([], False)
    ])
    def test_endpoint_profile_append(self, profiles, m_append_profiles_called):
        """
        Test appending profiles on an endpoint calls correct functions
        """
        with patch("calico_ctl.endpoint.client", autospec=True) as m_client:
            hostname = "m_hostname"
            orchestrator_id = "m_orchestrator_id"
            workload_id = "m_workload_id"
            endpoint_id = "m_endpoint_id"
            endpoint.endpoint_profile_append(hostname,
                                             orchestrator_id,
                                             workload_id,
                                             endpoint_id,
                                             profiles)

            self.assertEqual(m_client.append_profiles_to_endpoint.called,
                             m_append_profiles_called)
            if m_append_profiles_called:
                m_client.append_profiles_to_endpoint.assert_called_once_with(
                                               profiles,
                                               hostname=hostname,
                                               orchestrator_id=orchestrator_id,
                                               workload_id=workload_id,
                                               endpoint_id=endpoint_id)

    @parameterized.expand([
        (['profile-1', 'profile-2', 'profile-3'], True),
        (['test_prof'], True),
        ([], False)
    ])
    def test_endpoint_profile_remove(self, profiles, m_remove_profiles_called):
        """
        Test removing profiles from an endpoint calls correct functions.
        """
        with patch("calico_ctl.endpoint.client", autospec=True) as m_client:
            hostname = "m_hostname"
            orchestrator_id = "m_orchestrator_id"
            workload_id = "m_workload_id"
            endpoint_id = "m_endpoint_id"
            endpoint.endpoint_profile_remove(hostname,
                                             orchestrator_id,
                                             workload_id,
                                             endpoint_id,
                                             profiles)

            self.assertEqual(m_client.remove_profiles_from_endpoint.called,
                             m_remove_profiles_called)
            if m_remove_profiles_called:
                m_client.remove_profiles_from_endpoint.assert_called_once_with(
                                               profiles,
                                               hostname=hostname,
                                               orchestrator_id=orchestrator_id,
                                               workload_id=workload_id,
                                               endpoint_id=endpoint_id)