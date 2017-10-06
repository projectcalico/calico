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

from neutron.agent.linux import interface
try:
    from neutron.conf.agent import common as config
except ImportError:
    # Neutron code prior to 7f23ccc (15th March 2017).
    from neutron.agent.common import config
from neutron.tests import base

from networking_calico.agent.linux.interface import RoutedInterfaceDriver
from networking_calico.compat import cfg


class _TestInterfaceDriverMixin(object):
    # mock out base driver class __init__ that may attempt to access
    # network_device_mtu itself, which may not work for some tests that
    # validate calico driver behaviour for the option not being registered
    @mock.patch.object(interface.LinuxInterfaceDriver, '__init__')
    @mock.patch('neutron.agent.linux.ip_lib.IPWrapper.add_dummy')
    def _test_plug_new_mtu(self, passed_mtu, expected_mtu, dummy, *mocks):
        self.driver = RoutedInterfaceDriver(cfg.CONF)
        # we mocked out base __init__ that sets self.conf, so we should set it
        # explicitly here for next calls on the driver to work
        self.driver.conf = cfg.CONF
        kwargs = {'mtu': passed_mtu} if passed_mtu else {}
        self.driver.plug_new(
            'net-id', 'port-id', 'device-name', 'mac-address', **kwargs)
        set_mtu = dummy.return_value.link.set_mtu
        if expected_mtu:
            set_mtu.assert_called_with(expected_mtu)
        else:
            self.assertFalse(set_mtu.called)


class TestInterfaceDriver(base.BaseTestCase, _TestInterfaceDriverMixin):
    def setUp(self):
        super(TestInterfaceDriver, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch.object(interface.LinuxInterfaceDriver, 'init_l3')
    def test_init_l3(self, init_l3, ipdev_cls):
        self.driver = RoutedInterfaceDriver(cfg.CONF)
        self.driver.init_l3('ns-dhcp', ['10.65.0.1/24'])
        init_l3.assert_called_with('ns-dhcp', ['10.65.0.1/24'])
        ipdev_cls.assert_called_with('ns-dhcp')
        ipdev = ipdev_cls.return_value
        ipdev.route.delete_onlink_route.assert_called_with('10.65.0.0/24')

    def test_plug_new_mtu_None(self):
        self._test_plug_new_mtu(None, None)

    def test_plug_new_mtu_network_device_mtu_trumps(self):
        try:
            cfg.CONF.set_override('network_device_mtu', 2000)
        except cfg.NoSuchOptError:
            self.skipTest('network_device_mtu option missing')
        self._test_plug_new_mtu(3000, 2000)

    def test_plug_new_mtu_passed_network_device_mtu_unset(self):
        self._test_plug_new_mtu(2000, 2000)


class TestInterfaceDriverMissingNetworkDeviceMtu(base.BaseTestCase,
                                                 _TestInterfaceDriverMixin):
    def setUp(self):
        super(TestInterfaceDriverMissingNetworkDeviceMtu, self).setUp()
        config.register_interface_driver_opts_helper(cfg.CONF)

    def test_plug_new_mtu_None(self):
        self._test_plug_new_mtu(None, None)

    def test_plug_new_mtu_passed(self):
        self._test_plug_new_mtu(2000, 2000)
