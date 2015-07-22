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
from nose_parameterized import parameterized

from calico_ctl import pool


class TestPool(unittest.TestCase):

    @parameterized.expand([
        ({'add':1, '<CIDRS>':['127.a.0.1']}, True),
        ({'add':1, '<CIDRS>':['aa:bb::zz']}, True),
        ({'add':1, '<CIDRS>':['1.2.3.4']}, False),
        ({'add':1, '<CIDRS>':['1.2.3.0/24', '8.8.0.0/16']}, False),
        ({'add':1, '<CIDRS>':['aa:bb::ff']}, False),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.0',
          '<END_IP>':'1.2.3.255'}, False),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.255',
          '<END_IP>':'1.2.3.1'}, True),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.0',
          '<END_IP>':'bad'}, True),
        ({'range':1, 'add':1, '<START_IP>':'bad',
          '<END_IP>':'1.2.3.1'}, True),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.255',
          '<END_IP>':'aaaa::'}, True),
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl pool command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.validate_arguments(case)

            # Call method under test for each test case
            self.assertEqual(m_sys_exit.called, sys_exit_called)
