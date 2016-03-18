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
