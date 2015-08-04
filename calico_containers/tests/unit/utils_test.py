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

from calico_ctl import utils


class TestUtils(unittest.TestCase):

    @parameterized.expand([
        ('127.a.0.1', False),
        ('aa:bb::zz', False),
        ('1.2.3.4', True),
        ('1.2.3.0/24', True),
        ('aa:bb::ff', True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', True),
        ('4294967295', False)
    ])
    def test_validate_cidr(self, cidr, expected_result):
        """
        Test validate_cidr function in calico_ctl utils
        """
        # Call method under test
        test_result = utils.validate_cidr(cidr)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('1.2.3.4', 4, True),
        ('1.2.3.4', 6, False),
        ('1.2.3.4', 4, True),
        ('1.2.3.0/24', 4, False),
        ('aa:bb::ff', 4, False),
        ('aa:bb::ff', 6, True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', 6, True),
        ('4294967295', 4, True),
        ('5000000000', 4, False)
    ])
    def test_validate_ip(self, ip, version, expected_result):
        """
        Test validate_ip function in calico_ctl utils
        """
        # Call method under test
        test_result = utils.validate_ip(ip, version)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('abcdefghijklmnopqrstuvwxyz', True),
        ('0123456789', True),
        ('profile_1', True),
        ('profile-1', True),
        ('profile 1', False),
        ('profile.1', True),
        ('!', False),
        ('@', False),
        ('#', False),
        ('$', False),
        ('%', False),
        ('^', False),
        ('&', False),
        ('*', False),
        ('()', False)
    ])
    def test_validate_characters(self, input_string, expected_result):
        """
        Test validate_characters function in calico_ctl utils
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            test_result = utils.validate_characters(input_string)

            # Assert expected result
            self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('1.2.3.4', False),
        ('abcde', False),
        ('aa:bb::cc:1234', False),
        ('aa::256', False),
        ('aa...bb:256', False),
        ('aa:256', True),
        ('1.2.3.244:256', True),
        ('1.2.a.244:256', True),
        ('-asr:100', False),
        ('asr-:100', False),
        ('asr-temp-test.thr.yes-33:100', True),
        ('asr-temp-test.-thr.yes-33:100', False),
        ('asr-temp-test.thr-.yes-33:100', False),
        ('asr-temp-test.thr-.yes-33:100', False),
        ('validhostname:0', False),
        ('validhostname:65536', False),
        ('validhostname:1', True),
        ('validhostname:65535', True),
        ('#notvalidhostname:65535', False),
        ('verylong' * 100 + ':200', False),
        ('12.256.122.43:aaa', False)
    ])
    def test_validate_hostname_port(self, input_string, expected_result):
        """
        Test validate_hostname_port function.

        This also tests validate_hostname which is invoked from
        validate_hostname_port.
        """
        test_result = utils.validate_hostname_port(input_string)

        # Assert expected result
        self.assertEqual(expected_result, test_result)

