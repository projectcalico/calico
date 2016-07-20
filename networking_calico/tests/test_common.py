#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
import unittest

from networking_calico.common import config


class TestConfig(unittest.TestCase):

    def test_additional_options_registered(self):
        add_opt = cfg.StrOpt('test_option', default='test')
        config.register_options(cfg.CONF, additional_options=[add_opt])
        self.assertEqual(cfg.CONF['calico']['test_option'], 'test')
