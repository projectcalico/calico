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
from nose.tools import assert_raises
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
        (["1.2.3.4"], 4, True),
        (["1.2.3.4"], None, True),
        (["aa:bb::zz"], 6, False),
        (["aa:bb::zz"], None, False),
        (["10.0.0.1", "11.0.0.1", "11.0.0.1"], 4, True),
        (["10.0.0.1", "11.0.0.1", "11.0.0.1"], None, True),
        (["1111:2222:3333:4444:5555:6666:7777:8888", "a::b"], 6, True),
        (["1111:2222:3333:4444:5555:6666:7777:8888", "a::b", "1234::1"],
                                                                    None, True),
        (["127.1.0.1", "dead:beef"], None, False),
        (["aa:bb::zz"], 4, False),
        (["1.2.3.4"], 6, False),
        (["0bad:beef", "1.2.3.4"], 4, False),
        (["0bad:beef", "1.2.3.4"], 6, False),
        (["0bad:beef", "1.2.3.4"], None, False),
    ])
    def test_validate_cidr_versions(self, cidr_list, ip_version, expected_result):
        """
        Test validate_cidr_versions function in calico_ctl utils
        """
        # Call method under test
        test_result = utils.validate_cidr_versions(cidr_list,
                                                   ip_version=ip_version)

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


    @patch('os.path.exists', autospec=True)
    def test_ipv6_enabled(self, m_exists):
        """
        Test ipv6_enabled.
        """
        for rc in (True, False):
            m_exists.return_value = rc
            self.assertEquals(rc, utils.ipv6_enabled())
            m_exists.assert_called_with("/proc/sys/net/ipv6")


class TestUrlGetter(unittest.TestCase):
    def setUp(self):
        self.getter = utils.URLGetter()

    def test_404_response(self):
        url = "http:/somefake/url"
        fp = None
        errcode = 404
        msg = "Some message"
        headers = None
        assert_raises(IOError,
                      self.getter.http_error_default,
                      url, fp, errcode, msg, headers)
