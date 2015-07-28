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
