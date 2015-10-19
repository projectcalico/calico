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
from mock import patch, Mock, call
from sh import Command, ErrorReturnCode
from subprocess32 import CalledProcessError
from nose_parameterized import parameterized
from calico_ctl.checksystem import check_system, _check_modules


class TestCheckSystem(unittest.TestCase):

    @patch('calico_ctl.checksystem.enforce_root', autospec=True)
    @patch('calico_ctl.checksystem._check_modules', autospec=True, return_value=True)
    @patch('calico_ctl.checksystem._check_docker_version', autospec=True, return_value=True)
    def test_check_system(self, m_check_docker_version,
                          m_check_kernel_modules, m_enforce_root):
        """
        Test for check_system when all checks pass

        Assert that the function returns True
        """
        # Call method under test
        test_return = check_system(quit_if_error=True)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_check_kernel_modules.assert_called_once_with()
        m_check_docker_version.assert_called_once_with(False)
        self.assertTrue(test_return)

    @parameterized.expand([
        (True, False),
        (False, True),
    ])
    @patch('calico_ctl.checksystem.enforce_root', autospec=True)
    @patch('calico_ctl.checksystem._check_modules', autospec=True)
    @patch('calico_ctl.checksystem._check_docker_version', autospec=True)
    def test_check_system_bad_state_do_not_quit(
            self, kernel_status, docker_version_status,
            m_check_docker_version, m_check_kernel_modules, m_enforce_root):
        """
        Test for check_system when one of the system checks fails

        This test does not quit if there is an error -
        Assert that the function returns False

        :param kernel_status: return_value for _check_modules
        :param docker_version_status: return_value for _check_docker_version
        """
        # Set up mock objects
        m_check_kernel_modules.return_value = kernel_status
        m_check_docker_version.return_value = docker_version_status

        # Call method under test without exiting if error detected
        test_return = check_system(quit_if_error=False)

        # Assert
        self.assertFalse(test_return)

    @parameterized.expand([
        (True, False),
        (False, True),
    ])
    @patch('calico_ctl.checksystem.enforce_root', autospec=True)
    @patch('calico_ctl.checksystem._check_modules', autospec=True)
    @patch('calico_ctl.checksystem._check_docker_version', autospec=True)
    def test_check_system_bad_state_quit(
            self, kernel_status, docker_version_status,
            m_check_docker_version, m_check_kernel_modules, m_enforce_root):
        """
        Test for check_system when one of the system checks fails

        This test exits if there is a detected error -
        Assert that the system exits

        :param kernel_status: return_value for _check_modules patch
        :param docker_version_status: return_value for _check_docker_version patch
        """
        # Set up mock objects
        m_check_kernel_modules.return_value = kernel_status
        m_check_docker_version.return_value = docker_version_status

        # Call method under test expecting a SystemExit when fail detected
        self.assertRaises(SystemExit, check_system, quit_if_error=True)

    # Numbered modules exist within the mocked files and should be valid
    # check_modules should return False if searching for invalid module
    @parameterized.expand([
        (["mod_one", "mod_four"], True),
        (["mod_four", "mod_five"], True),
        (["mod_invalid"], False),
        (["mod_one", "mod_invalid"], False),
        (["mod_four", "mod_invalid"], False),
    ])
    @patch('__builtin__.open', autospec=True)
    @patch('sys.stderr', autospec=True)
    @patch('calico_ctl.checksystem.check_output', autospec=True, return_value="version")
    def test_check_modules_double_open(self, requirements, expected_return,
                                       m_get_version, m_stderr, m_open):
        """Test _check_module for different requirements (opening 2 files)
        Use parameterized requirements to test a variety of states in which
        modules may or not be found. Check the number of calls to open().
        Numbered modules exist within the mocked files and should be valid.
        check_modules should return False if searching for the invalid module.
        """
        m_file = Mock()
        m_file.readlines.side_effect = [["/mod_one.ko", "/mod_two.ko", "/mod_three.ko"], # Mocked Available modules
                                        ["/mod_four.ko", "/mod_five.ko"],                # Mocked Builtin modules
                                       ]
        m_open.return_value = m_file

        with patch('calico_ctl.checksystem.REQUIRED_MODULES', requirements):
            return_val = _check_modules()

        self.assertEquals(return_val, expected_return)
        m_open.assert_has_calls([call("/lib/modules/version/modules.dep"),
                                 call().readlines(),
                                 call("/lib/modules/version/modules.builtin"),
                                 call().readlines(),
                                ])

    @parameterized.expand([
        (["mod_one", "mod_two"], True),
        (["mod_three"], True),
    ])
    @patch('__builtin__.open', autospec=True)
    @patch('sys.stderr', autospec=True)
    @patch('calico_ctl.checksystem.check_output', autospec=True, return_value="version")
    def test_check_modules_single_open(self, requirements, expected_return,
                                       m_get_version, m_stderr, m_open):
        """Test _check_module for different requirements (opening 1 file)
        Use parameterized requirements to test a variety of states in which
        modules may or not be found. Check the number of calls to open().
        Numbered modules exist within the mocked file and should be valid.
        """
        m_file = Mock()
        m_file.readlines.return_value = ["/mod_one.ko", "/mod_two.ko", "/mod_three.ko"] # Mocked Available modules

        m_open.return_value = m_file

        with patch('calico_ctl.checksystem.REQUIRED_MODULES', requirements):
            return_val = _check_modules()

        m_open.assert_called_once_with("/lib/modules/version/modules.dep")
        self.assertEquals(return_val, expected_return)

    @parameterized.expand([
        (["mod_one", "mod_two"], True),
        (["mod_three", "mod_invalid"], False),
    ])
    @patch('__builtin__.open', autospec=True)
    @patch('sys.stderr', autospec=True)
    @patch('calico_ctl.checksystem.check_output', autospec=True)
    def test_check_modules_lsmod(self, requirements, expected_return,
                                 m_check_out, m_stderr, m_open):
        """Test _check_module using lsmod
        Cause failure on file open and check_system should
        find modules in lsmod output.
        """
        m_open.side_effect = CalledProcessError
        m_check_out.return_value = "mod_one\n mod_two\n mod_three\n"

        with patch('calico_ctl.checksystem.REQUIRED_MODULES', requirements):
            return_val = _check_modules()

        self.assertEquals(return_val, expected_return)

    @patch('sys.stderr', autospec=True)
    @patch('calico_ctl.checksystem.check_output', autospec=True)
    def test_check_modules_error(self, m_check_out, m_stderr):
        """Test _check_module lsmod failure
        All check_output calls raise an error, meaning check_system
        should return false.
        """
        m_check_out.side_effect = CalledProcessError
        return_val = _check_modules()
        self.assertFalse(return_val)
