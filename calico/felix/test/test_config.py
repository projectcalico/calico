# -*- coding: utf-8 -*-
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
"""
felix.test.test_config
~~~~~~~~~~~~~~~~~~~~~~

Tests of the config module.
"""
import logging
import unittest
from mock import patch
from calico.felix import config

_log = logging.getLogger(__name__)


class TestConig(unittest.TestCase):
    @patch("ConfigParser.ConfigParser", autospec=True)
    def test_env_var_override(self, m_ConfigParser):
        """
        Test environment variables override config options,
        """
        with patch.dict("os.environ", {"GLOBAL_ETCDHOST": "testhost",
                                       "GLOBAL_ETCDPORT": "1234"}):
            cfg = config.Config("/tmp/felix.cfg")
        self.assertEqual(cfg.ETCD_HOST, "testhost")
        self.assertEqual(cfg.ETCD_PORT, 1234)