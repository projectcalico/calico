# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
felix.test.test_devices
~~~~~~~~~~~

Test the device handling code.
"""
import logging
import mock
import sys
import uuid
from contextlib import nested

from netaddr import IPAddress

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import calico.felix.devices as devices
import calico.felix.futils as futils
import calico.felix.test.stub_utils as stub_utils

# Logger
log = logging.getLogger(__name__)

# Canned mock calls representing clean entry to/exit from a context manager.
M_ENTER = mock.call().__enter__()
M_CLEAN_EXIT = mock.call().__exit__(None, None, None)


class TestDevices(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch("os.path.exists", autospec=True, return_value=True)
    @mock.patch("calico.felix.devices._write_proc_sys",
                autospec=True)
    @mock.patch("calico.felix.devices._read_proc_sys",
                autospec=True, return_value="1")
    def test_configure_global_kernel_config(self,
                                            m_read_proc_sys,
                                            m_write_proc_sys,
                                            m_exists):
        m_config = mock.Mock()
        m_config.IGNORE_LOOSE_RPF = True
        devices.configure_global_kernel_config(m_config)
        m_write_proc_sys.assert_called_once_with(
            "/proc/sys/net/ipv4/conf/default/rp_filter", "1"
        )

    @mock.patch("os.path.exists", autospec=True, return_value=False)
    @mock.patch("calico.felix.devices._write_proc_sys",
                autospec=True)
    @mock.patch("calico.felix.devices._read_proc_sys",
                autospec=True, return_value="1")
    def test_configure_global_kernel_config_no_sysfs(self,
                                                     m_read_proc_sys,
                                                     m_write_proc_sys,
                                                     m_exists):
        m_config = mock.Mock()
        m_config.IGNORE_LOOSE_RPF = False
        self.assertRaises(devices.BadKernelConfig,
                          devices.configure_global_kernel_config, m_config)

    def test_configure_global_kernel_config_bad_rp_filter(self):
        m_config = mock.Mock()
        m_config.IGNORE_LOOSE_RPF = False
        with mock.patch("calico.felix.devices._read_proc_sys",
                        autospec=True, return_value="2") as m_read_proc_sys:
            self.assertRaises(devices.BadKernelConfig,
                              devices.configure_global_kernel_config,
                              m_config)

    @mock.patch("calico.felix.devices._write_proc_sys",
                autospec=True)
    @mock.patch("calico.felix.devices._read_proc_sys",
                autospec=True)
    def test_configure_global_kernel_config_bad_rp_filter_ignored(self, m_rps, m_wps):
        m_config = mock.Mock()
        m_config.IGNORE_LOOSE_RPF = True
        m_rps.return_value = "2"
        devices.configure_global_kernel_config(m_config)

    def test_read_proc_sys(self):
        m_open = mock.mock_open(read_data="1\n")
        with mock.patch('__builtin__.open', m_open, create=True):
            result = devices._read_proc_sys("/proc/sys/foo/bar")
        calls = [mock.call('/proc/sys/foo/bar', 'rb'),
                 M_ENTER, mock.call().read(), M_CLEAN_EXIT]
        m_open.assert_has_calls(calls)
        self.assertEqual(result, "1")

    def test_interface_exists(self):
        with mock.patch("os.path.exists", autospec=True) as m_exists:
            m_exists.return_value = False
            self.assertFalse(devices.interface_exists("tap1234"))
            m_exists.return_value = True
            self.assertTrue(devices.interface_exists("tap1234"))
        self.assertEqual(m_exists.mock_calls,
                         [mock.call("/sys/class/net/tap1234"),
                          mock.call("/sys/class/net/tap1234")])

    def test_add_route(self):
        tap = "tap" + str(uuid.uuid4())[:11]
        mac = stub_utils.get_mac()
        retcode = futils.CommandOutput("", "")

        type = futils.IPV4
        ip = "1.2.3.4"
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            devices.add_route(type, ip, tap, mac)
            futils.check_call.assert_any_call(['arp', '-s', ip, mac, '-i', tap])
            futils.check_call.assert_called_with(["ip", "route", "replace", ip, "dev", tap])

        with mock.patch("calico.felix.futils.check_call") as m_check_call:
            devices.add_route(type, ip, tap, None)

        type = futils.IPV6
        ip = "2001::"
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            devices.add_route(type, ip, tap, mac)
            futils.check_call.assert_called_with(["ip", "-6", "route", "replace", ip, "dev", tap])

        with mock.patch("calico.felix.futils.check_call") as m_check_call:
            devices.add_route(type, ip, tap, None)

    def test_del_route(self):
        tap = "tap" + str(uuid.uuid4())[:11]
        retcode = futils.CommandOutput("", "")

        type = futils.IPV4
        ip = "1.2.3.4"
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            devices.del_route(type, ip, tap)
            futils.check_call.assert_any_call(['arp', '-d', ip, '-i', tap])
            futils.check_call.assert_called_with(["ip", "route", "del", ip, "dev", tap])

        type = futils.IPV6
        ip = "2001::"
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            devices.del_route(type, ip, tap)
            futils.check_call.assert_called_once_with(["ip", "-6", "route", "del", ip, "dev", tap])

    def test_set_routes_mac_not_set(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        with mock.patch("calico.felix.futils.check_call") as m_check_call:
            devices.set_routes(type, ips, interface)

    def test_set_routes_arp_ipv4_only(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        with self.assertRaisesRegexp(ValueError,
                                     "reset_arp may only be supplied for "
                                     "IPv4"):
            devices.set_routes(futils.IPV6, ips, interface, mac=mac,
                               reset_arp=True)

    def test_set_routes_mainline(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        calls = [mock.call(['arp', '-s', "1.2.3.4", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "1.2.3.4", "dev", interface]),
                 mock.call(['arp', '-s', "2.3.4.5", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "2.3.4.5", "dev", interface])]

        with mock.patch('calico.felix.futils.check_call',
                        return_value=futils.CommandOutput("", "")):
            with mock.patch('calico.felix.devices.list_interface_route_ips',
                            return_value=set()):
                devices.set_routes(type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)

    def test_set_routes_nothing_to_do(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        retcode = futils.CommandOutput("", "")
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        with mock.patch('calico.felix.futils.check_call',
                        return_value=retcode):
            with mock.patch('calico.felix.devices.list_interface_route_ips',
                            return_value=ips):
                devices.set_routes(type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, 0)

    def test_set_routes_changed_ips(self):
        ip_type = futils.IPV4
        current_ips = set(["2.3.4.5", "3.4.5.6"])
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        retcode = futils.CommandOutput("", "")
        calls = [mock.call(['arp', '-s', "1.2.3.4", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "1.2.3.4", "dev",
                            interface]),
                 mock.call(['arp', '-d', "3.4.5.6", '-i', interface]),
                 mock.call(["ip", "route", "del", "3.4.5.6", "dev",
                            interface])]

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            with mock.patch('calico.felix.devices.list_interface_route_ips',
                            return_value=current_ips):
                devices.set_routes(ip_type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)

    def test_set_routes_changed_ips_reset_arp(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        retcode = futils.CommandOutput("", "")
        current_ips = set(["2.3.4.5", "3.4.5.6"])
        calls = [mock.call(['arp', '-s', "1.2.3.4", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "1.2.3.4", "dev", interface]),
                 mock.call(['arp', '-s', "2.3.4.5", mac, '-i', interface]),
                 mock.call(['arp', '-d', "3.4.5.6", '-i', interface]),
                 mock.call(["ip", "route", "del", "3.4.5.6", "dev", interface])]
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            with mock.patch('calico.felix.devices.list_interface_route_ips',
                            return_value=current_ips):
                devices.set_routes(type, ips, interface, mac, reset_arp=True)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)

    def test_set_routes_add_ips(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        retcode = futils.CommandOutput("", "")
        current_ips = set()
        calls = [mock.call(['arp', '-s', "1.2.3.4", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "1.2.3.4", "dev",
                            interface]),
                 mock.call(['arp', '-s', "2.3.4.5", mac, '-i', interface]),
                 mock.call(["ip", "route", "replace", "2.3.4.5", "dev",
                            interface])]

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            with mock.patch('calico.felix.devices.list_interface_route_ips',
                            return_value=current_ips):
                devices.set_routes(type, ips, interface, mac, reset_arp=True)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)

    def test_list_interface_no_ips(self):
        retcode = futils.CommandOutput(
            "7: tunl0@NONE: <NOARP,UP,LOWER_UP> mtu 1440 qdisc noqueue "
            "state UNKNOWN group default\n"
            "    link/ipip 0.0.0.0 brd 0.0.0.0\n",
            ""
        )
        with mock.patch('calico.felix.futils.check_call',
                        return_value=retcode) as m_check_call:
            ips = devices.list_interface_ips(futils.IPV4, "tunl0")
            self.assertEqual(
                m_check_call.mock_calls,
                [mock.call(["ip", "addr", "list", "dev", "tunl0"])]
            )
            self.assertEqual(ips, set())

    def test_list_interface_with_ips(self):
        retcode = futils.CommandOutput(
            "7: tunl0@NONE: <NOARP,UP,LOWER_UP> mtu 1440 qdisc noqueue "
            "state UNKNOWN group default\n"
            "    link/ipip 0.0.0.0 brd 0.0.0.0\n"
            "    inet 10.0.3.1/24 brd 10.0.3.255 scope global tunl0\n"
            "    inet 10.0.3.2/24 brd 10.0.3.255 scope global tunl0\n",
            ""
        )
        with mock.patch('calico.felix.futils.check_call',
                        return_value=retcode) as m_check_call:
            ips = devices.list_interface_ips(futils.IPV4, "tunl0")
            self.assertEqual(
                m_check_call.mock_calls,
                [mock.call(["ip", "addr", "list", "dev", "tunl0"])]
            )
            self.assertEqual(ips, set([IPAddress("10.0.3.1"),
                                       IPAddress("10.0.3.2")]))

    def test_list_interface_v6_with_ips(self):
        retcode = futils.CommandOutput(
            "7: tunl0@NONE: <NOARP,UP,LOWER_UP> mtu 1440 qdisc noqueue "
            "state UNKNOWN group default\n"
            "    link/ipip 0.0.0.0 brd 0.0.0.0\n"
            "    inet6 5678::/64 brd foobar scope global tunl0\n"
            "    inet6 ABcd::/64 brd foobar scope global tunl0\n"
            # Allow for dotted quad translated v4 addresses, just in case.
            "    inet6 ::ffff:192.0.2.128/128 brd foobar scope global tunl0\n",
            ""
        )
        with mock.patch('calico.felix.futils.check_call',
                        return_value=retcode) as m_check_call:
            ips = devices.list_interface_ips(futils.IPV6, "tunl0")
            self.assertEqual(
                m_check_call.mock_calls,
                [mock.call(["ip", "-6", "addr", "list", "dev", "tunl0"])]
            )
            self.assertEqual(ips, set([IPAddress("5678::"),
                                       IPAddress("abcd::"),
                                       IPAddress("::ffff:c000:0280")]))

    def test_list_ips_by_iface_v4_mainline(self):
        retval = futils.CommandOutput(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default \n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "       valid_lft forever preferred_lft forever\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n"
            "    inet 192.168.171.128/24 brd 192.168.171.255 scope global eth0\n"
            "       valid_lft forever preferred_lft forever\n"
            "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n"
            "    inet 172.16.171.5/24 brd 172.16.171.255 scope global eth1\n"
            "       valid_lft forever preferred_lft forever\n"
            "5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default \n"
            "    inet 172.17.0.1/16 scope global docker0\n"
            "       valid_lft forever preferred_lft forever\n"
            "6: lxcbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default \n"
            "    inet 10.0.3.1/24 brd 10.0.3.255 scope global lxcbr0\n"
            "       valid_lft forever preferred_lft forever\n"
            "    inet 10.0.3.2/24 brd 10.0.3.255 scope global lxcbr0\n"
            "       valid_lft forever preferred_lft forever\n",
            ""
        )

        with mock.patch('calico.felix.futils.check_call',
                        return_value=retval) as m_check_call:
            ips = devices.list_ips_by_iface(futils.IPV4)
        self.assertEqual(
            ips,
            {
                "lo": {IPAddress("127.0.0.1")},
                "eth0": {IPAddress("192.168.171.128")},
                "eth1": {IPAddress("172.16.171.5")},
                "docker0": {IPAddress("172.17.0.1")},
                "lxcbr0": {IPAddress("10.0.3.1"), IPAddress("10.0.3.2")},
            }
        )
        
    def test_list_ips_by_iface_v6_mainline(self):
        retval = futils.CommandOutput(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 \n"
            "    inet6 ::1/128 scope host \n"
            "       valid_lft forever preferred_lft forever\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qlen 1000\n"
            "    inet6 fe80::20c:29ff:fecb:c819/64 scope link \n"
            "       valid_lft forever preferred_lft forever\n"
            "4: mgmt0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \n"
            "    inet6 fe80::1/64 scope link \n"
            "       valid_lft forever preferred_lft forever\n"
            "    inet6 fe80::8872:90ff:fec4:f79e/64 scope link \n"
            "       valid_lft forever preferred_lft forever\n",
            ""
        )

        with mock.patch('calico.felix.futils.check_call',
                        return_value=retval) as m_check_call:
            ips = devices.list_ips_by_iface(futils.IPV6)
        self.assertEqual(
            ips,
            {
                "lo": {IPAddress("::1")},
                "eth0": {IPAddress("fe80::20c:29ff:fecb:c819")},
                "mgmt0": {IPAddress("fe80::1"),
                          IPAddress("fe80::8872:90ff:fec4:f79e")},
            }
        )

    def test_set_interface_ips(self):
        with mock.patch('calico.felix.futils.check_call',
                        autospec=True) as m_check_call:
            with mock.patch("calico.felix.devices.list_interface_ips",
                            autospec=True) as m_list_ips:
                m_list_ips.return_value = set([IPAddress("10.0.0.1"),
                                               IPAddress("10.0.0.2")])
                devices.set_interface_ips(
                    futils.IPV4,
                    "tunl0",
                    set([IPAddress("10.0.0.2"),
                         IPAddress("10.0.0.3")])
                )
                self.assertEqual(
                    m_check_call.mock_calls,
                    [
                        mock.call(["ip", "addr", "del", "10.0.0.1", "dev",
                                   "tunl0"]),
                        mock.call(["ip", "addr", "add", "10.0.0.3", "dev",
                                   "tunl0"]),
                    ]
                )

    def test_list_interface_route_ips(self):
        type = futils.IPV4
        tap = "tap" + str(uuid.uuid4())[:11]

        retcode = futils.CommandOutput("", "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_route_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertFalse(ips)

        stdout = "10.11.9.90  scope link"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_route_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["10.11.9.90"]))

        stdout = "10.11.9.90  scope link\nblah-di-blah not valid\nx\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_route_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["10.11.9.90"]))

        type = futils.IPV6
        stdout = "2001:: scope link\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_route_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "-6", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["2001::"]))

        stdout = "2001:: scope link\n\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_route_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "-6", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["2001::"]))

    def test_configure_interface_ipv4_mainline(self):
        m_open = mock.mock_open()
        tap = "tap" + str(uuid.uuid4())[:11]
        with mock.patch('__builtin__.open', m_open, create=True):
            devices.configure_interface_ipv4(tap)
        calls = [mock.call('/proc/sys/net/ipv4/conf/%s/rp_filter' % tap, 'wb'),
                 M_ENTER, mock.call().write('1'), M_CLEAN_EXIT,
                 mock.call('/proc/sys/net/ipv4/conf/%s/route_localnet' % tap, 'wb'),
                 M_ENTER, mock.call().write('1'), M_CLEAN_EXIT,
                 mock.call('/proc/sys/net/ipv4/conf/%s/proxy_arp' % tap, 'wb'),
                 M_ENTER, mock.call().write('1'), M_CLEAN_EXIT,
                 mock.call('/proc/sys/net/ipv4/neigh/%s/proxy_delay' %tap, 'wb'),
                 M_ENTER, mock.call().write('0'), M_CLEAN_EXIT,]
        m_open.assert_has_calls(calls)

    def test_configure_interface_ipv6_mainline(self):
        """
        Test that configure_interface_ipv6_mainline
            - opens and writes to the /proc system to enable proxy NDP on the
              interface.
            - calls ip -6 neigh to set up the proxy targets.

        Mainline test has two proxy targets.
        """
        m_open = mock.mock_open()
        rc = futils.CommandOutput("", "")
        if_name = "tap3e5a2b34222"
        proxy_target = "2001::3:4"

        open_patch = mock.patch('__builtin__.open', m_open, create=True)
        m_check_call = mock.patch('calico.felix.futils.check_call',
                                  return_value=rc)

        with nested(open_patch, m_check_call) as (_, m_check_call):
            devices.configure_interface_ipv6(if_name, proxy_target)
            calls = [mock.call('/proc/sys/net/ipv6/conf/%s/proxy_ndp' %
                               if_name,
                               'wb'),
                     M_ENTER,
                     mock.call().write('1'),
                     M_CLEAN_EXIT]
            m_open.assert_has_calls(calls)
            ip_calls = [mock.call(["ip", "-6", "neigh", "add", "proxy",
                                   str(proxy_target), "dev", if_name])]
            m_check_call.assert_has_calls(ip_calls)

    def test_interface_up_iface_up(self):
        """
        Test that interface_up returns True when an interface is up.
        """
        tap = "tap" + str(uuid.uuid4())[:11]

        with mock.patch('__builtin__.open') as open_mock:
            open_mock.return_value = mock.MagicMock(spec=file)
            file_obj = open_mock.return_value.__enter__.return_value
            file_obj.read.return_value = 'up\n'

            is_up = devices.interface_up(tap)

            open_mock.assert_called_with(
                '/sys/class/net/%s/operstate' % tap, 'r'
            )
            self.assertTrue(file_obj.read.called)
            self.assertTrue(is_up)

    def test_interface_up_iface_down(self):
        """
        Test that interface_up returns False when an interface is down.
        """
        tap = "tap" + str(uuid.uuid4())[:11]

        with mock.patch('__builtin__.open') as open_mock:
            open_mock.return_value = mock.MagicMock(spec=file)
            file_handle = open_mock.return_value.__enter__.return_value
            file_handle.read.return_value = 'down\n'

            is_up = devices.interface_up(tap)

            open_mock.assert_called_with(
                '/sys/class/net/%s/operstate' % tap, 'r'
            )
            self.assertTrue(file_handle.read.called)
            self.assertFalse(is_up)

    def test_interface_up3(self):
        """
        Test that interface_up returns False if it cannot read the flag.
        """
        tap = "tap" + str(uuid.uuid4())[:11]

        with mock.patch('__builtin__.open') as open_mock:
            open_mock.side_effect = IOError
            is_up = devices.interface_up(tap)
            self.assertFalse(is_up)

    @mock.patch("calico.felix.futils.check_call", autospec=True)
    def test_remove_conntrack(self, m_check_call):
        devices.remove_conntrack_flows(set(["10.0.0.1"]), 4)
        self.assertEqual(m_check_call.mock_calls, [
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--orig-src", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--orig-dst", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--reply-src", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--reply-dst", "10.0.0.1"]),
        ])

    @mock.patch("calico.felix.futils.check_call", autospec=True)
    def test_remove_conntrack_v6(self, m_check_call):
        devices.remove_conntrack_flows(set(["1234::1"]), 6)
        self.assertEqual(m_check_call.mock_calls, [
            mock.call(["conntrack", "--family", "ipv6", "--delete",
                       "--orig-src", "1234::1"]),
            mock.call(["conntrack", "--family", "ipv6", "--delete",
                       "--orig-dst", "1234::1"]),
            mock.call(["conntrack", "--family", "ipv6", "--delete",
                       "--reply-src", "1234::1"]),
            mock.call(["conntrack", "--family", "ipv6", "--delete",
                       "--reply-dst", "1234::1"]),
        ])

    @mock.patch("calico.felix.futils.check_call", autospec=True)
    def test_remove_conntrack_missing(self, m_check_call):
        m_check_call.side_effect = futils.FailedSystemCall(
            "message",
            [],
            1,
            "",
            "0 flow entries"
        )
        devices.remove_conntrack_flows(set(["10.0.0.1"]), 4)
        self.assertEqual(m_check_call.mock_calls, [
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--orig-src", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--orig-dst", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--reply-src", "10.0.0.1"]),
            mock.call(["conntrack", "--family", "ipv4", "--delete",
                       "--reply-dst", "10.0.0.1"]),
        ])

    @mock.patch("calico.felix.futils.check_call", autospec=True)
    def test_remove_conntrack_error(self, m_check_call):
        m_check_call.side_effect = futils.FailedSystemCall(
            "message",
            [],
            1,
            "",
            "unexpected error"
        )
        devices.remove_conntrack_flows(set(["10.0.0.1"]), 4)
        # Each call is retried 3 times.
        self.assertEqual(m_check_call.mock_calls,
            [mock.call(["conntrack", "--family", "ipv4", "--delete",
                        "--orig-src", "10.0.0.1"])] * 3 +
            [mock.call(["conntrack", "--family", "ipv4", "--delete",
                        "--orig-dst", "10.0.0.1"])] * 3 +
            [mock.call(["conntrack", "--family", "ipv4", "--delete",
                        "--reply-src", "10.0.0.1"])] * 3 +
            [mock.call(["conntrack", "--family", "ipv4", "--delete",
                        "--reply-dst", "10.0.0.1"])] * 3)
