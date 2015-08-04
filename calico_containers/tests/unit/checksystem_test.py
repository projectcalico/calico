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
from mock import patch, Mock
from calico_ctl.checksystem import _check_kernel_modules
from sh import Command, ErrorReturnCode
from nose_parameterized import parameterized
from calico_ctl.checksystem import check_system


class TestCheckSystem(unittest.TestCase):

    @patch("calico_ctl.checksystem.sh.Command", autospec=True)
    def test_check_mod_ipip(self, m_command):

        # Mock out sh.Command._create
        m_modprobe = Mock(Command)
        m_ip6tables = Mock(Command)

        def _create(cmd):
            if cmd == "modprobe":
                return m_modprobe
            elif cmd == "ip6tables":
                return m_ip6tables
            else:
                raise ValueError()
        m_command._create = _create

        def m_module_loaded(module):
            return module == "xt_set"

        with patch("calico_ctl.checksystem.module_loaded", m_module_loaded):
            result = _check_kernel_modules(False)

            # Fix = false means system is not OK.
            self.assertFalse(result)
            self.assertFalse(m_modprobe.called)
            m_ip6tables.assert_called_once_with("-L")

            # Reset mocks
            m_modprobe.reset_mock()
            m_ip6tables.reset_mock()

            result = _check_kernel_modules(True)

            # Fix = true should attempt to fix with modprobe.
            self.assertTrue(result)
            m_modprobe.assert_called_once_with("ipip")
            m_ip6tables.assert_called_once_with("-L")

            # Reset mocks
            m_modprobe.reset_mock()
            m_ip6tables.reset_mock()

            # Fix = true, but modprobe fails.
            m_modprobe.side_effect = ErrorReturnCode("modprobe ipip", "", "")
            result = _check_kernel_modules(True)

            self.assertFalse(result)
            m_modprobe.assert_called_once_with("ipip")
            m_ip6tables.assert_called_once_with("-L")

    @patch('calico_ctl.checksystem.enforce_root', autospec=True)
    @patch('calico_ctl.checksystem._check_kernel_modules', autospec=True, return_value=True)
    @patch('calico_ctl.checksystem._check_ip_forwarding', autospec=True, return_value=True)
    @patch('calico_ctl.checksystem._check_docker_version', autospec=True, return_value=True)
    def test_check_system(self, m_check_docker_version, m_check_ip_forwarding,
                          m_check_kernel_modules, m_enforce_root):
        """
        Test for check_system when all checks pass

        Assert that the function returns True
        """
        # Call method under test
        test_return = check_system(fix=False, quit_if_error=True)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_check_kernel_modules.assert_called_once_with(False)
        m_check_ip_forwarding.assert_called_once_with(False)
        m_check_docker_version.assert_called_once_with()
        self.assertTrue(test_return)

    @parameterized.expand([
        (True, True, False),
        (True, False, True),
        (False, True, True),
    ])
    def test_check_system_bad_state_do_not_quit(
            self, kernel_status, ip_forwarding_status, docker_version_status):
        """
        Test for check_system when one of the system checks fails

        This test does not quit if there is an error -
        Assert that the function returns False

        :param kernel_status: return_value for _check_kernel_modules
        :param ip_forwarding_status: return_value for _check_ip_forwarding
        :param docker_version_status: return_value for _check_docker_version
        """
        with patch('calico_ctl.checksystem.enforce_root', autospec=True) \
                     as m_enforce_root, \
             patch('calico_ctl.checksystem._check_kernel_modules', autospec=True) \
                     as m_check_kernel_modules, \
             patch('calico_ctl.checksystem._check_ip_forwarding', autospec=True) \
                     as m_check_ip_forwarding, \
             patch('calico_ctl.checksystem._check_docker_version', autospec=True) \
                        as m_check_docker_version:
            # Set up mock objects
            m_check_kernel_modules.return_value = kernel_status
            m_check_ip_forwarding.return_value = ip_forwarding_status
            m_check_docker_version.return_value = docker_version_status

            # Call method under test without exiting if error detected
            test_return = check_system(fix=False, quit_if_error=False)

            # Assert
            m_enforce_root.assert_called_once_with()
            self.assertFalse(test_return)

    @parameterized.expand([
        (True, True, False),
        (True, False, True),
        (False, True, True),
    ])
    def test_check_system_bad_state_quit(
            self, kernel_status, ip_forwarding_status, docker_version_status):
        """
        Test for check_system when one of the system checks fails

        This test exits if there is a detected error -
        Assert that the system exits

        :param kernel_status: return_value for _check_kernel_modules patch
        :param ip_forwarding_status: return_value for _check_ip_forwarding patch
        :param docker_version_status: return_value for _check_docker_version patch
        """
        with patch('calico_ctl.checksystem.enforce_root', autospec=True) \
                     as m_enforce_root, \
             patch('calico_ctl.checksystem._check_kernel_modules', autospec=True) \
                     as m_check_kernel_modules, \
             patch('calico_ctl.checksystem._check_ip_forwarding', autospec=True) \
                     as m_check_ip_forwarding, \
             patch('calico_ctl.checksystem._check_docker_version', autospec=True) \
                     as m_check_docker_version:
            # Set up mock objects
            m_check_kernel_modules.return_value = kernel_status
            m_check_ip_forwarding.return_value = ip_forwarding_status
            m_check_docker_version.return_value = docker_version_status

            # Call method under test expecting a SystemExit when fail detected
            self.assertRaises(SystemExit, check_system, fix=False, quit_if_error=True)

            # Assert
            m_enforce_root.assert_called_once_with()
