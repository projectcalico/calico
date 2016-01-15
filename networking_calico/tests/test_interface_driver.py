# Copyright 2016 Metaswitch Networks
#
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

import mock

from networking_calico.agent.linux.interface import RoutedInterfaceDriver
from neutron.agent.common import config
from neutron.agent.linux import interface
from neutron.tests import base
from oslo_config import cfg


class TestInterfaceDriver(base.BaseTestCase):
    def setUp(self):
        super(TestInterfaceDriver, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)
        config.register_use_namespaces_opts_helper(cfg.CONF)
        cfg.CONF.register_opts(interface.OPTS)
        cfg.CONF.set_override('use_namespaces', False)

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch.object(interface.LinuxInterfaceDriver, 'init_l3')
    def test_init_l3(self, init_l3, ipdev_cls):
        self.driver = RoutedInterfaceDriver(cfg.CONF)
        self.driver.init_l3('ns-dhcp', ['10.65.0.1/24'])
        init_l3.assert_called_with('ns-dhcp',
                                   ['10.65.0.1/24'],
                                   None,
                                   [],
                                   None,
                                   [])
        ipdev_cls.assert_called_with('ns-dhcp', namespace=None)
        ipdev = ipdev_cls.return_value
        ipdev.route.delete_onlink_route.assert_called_with('10.65.0.0/24')
