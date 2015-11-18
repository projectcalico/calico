# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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

    def test_configure_global_kernel_config(self):
        with mock.patch("calico.felix.devices._read_proc_sys",
                        autospec=True, return_value="1") as m_read_proc_sys:
            with mock.patch("calico.felix.devices._write_proc_sys",
                            autospec=True) as m_write_proc_sys:
                devices.configure_global_kernel_config()
        m_write_proc_sys.assert_called_once_with(
            "/proc/sys/net/ipv4/conf/default/rp_filter", "1"
        )

    def test_configure_global_kernel_config_bad_rp_filter(self):
        with mock.patch("calico.felix.devices._read_proc_sys",
                        autospec=True, return_value="2") as m_read_proc_sys:
            self.assertRaises(devices.BadKernelConfig,
                              devices.configure_global_kernel_config)

    def test_read_proc_sys(self):
        m_open = mock.mock_open(read_data="1\n")
        with mock.patch('__builtin__.open', m_open, create=True):
            result = devices._read_proc_sys("/proc/sys/foo/bar")
        calls = [mock.call('/proc/sys/foo/bar', 'rb'),
                 M_ENTER, mock.call().read(), M_CLEAN_EXIT]
        m_open.assert_has_calls(calls)
        self.assertEqual(result, "1")

    def test_interface_exists(self):
        tap = "tap" + str(uuid.uuid4())[:11]

        args = []
        retcode = 1
        stdout = ""

        # Check we correctly handle error messages for a missing interface,
        # and do so for all supported flavors of Linux.
        error_messages = [
            "Device \"%s\" does not exist." % tap,  # Ubuntu/RHEL
            "ip: can't find device '%s'" % tap,     # Alpine
        ]

        for stderr in error_messages:
	    err = futils.FailedSystemCall("From test", args, retcode, stdout, stderr)

	    with mock.patch('calico.felix.futils.check_call', side_effect=err):
	        self.assertFalse(devices.interface_exists(tap))
	        futils.check_call.assert_called_with(["ip", "link", "list", tap])

        with mock.patch('calico.felix.futils.check_call'):
            self.assertTrue(devices.interface_exists(tap))
            futils.check_call.assert_called_with(["ip", "link", "list", tap])

        stderr = "Another error."
        err = futils.FailedSystemCall("From test", args, retcode, stdout, stderr)
        with mock.patch('calico.felix.futils.check_call', side_effect=err):
            with self.assertRaises(futils.FailedSystemCall):
                devices.interface_exists(tap)

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

        with self.assertRaisesRegexp(ValueError,
                                     "mac must be supplied if ip is provided"):
            devices.add_route(type, ip, tap, None)

        type = futils.IPV6
        ip = "2001::"
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            devices.add_route(type, ip, tap, mac)
            futils.check_call.assert_called_with(["ip", "-6", "route", "replace", ip, "dev", tap])

        with self.assertRaisesRegexp(ValueError,
                                     "mac must be supplied if ip is provided"):
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

    def test_set_routes_mac_required(self):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        with self.assertRaisesRegexp(ValueError,
                                     "mac must be supplied if ips is not "
                                     "empty"):
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

    @mock.patch("calico.felix.devices.remove_conntrack_flows", autospec=True)
    def test_set_routes_mainline(self, m_remove_conntrack):
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
            with mock.patch('calico.felix.devices.list_interface_ips',
                            return_value=set()):
                devices.set_routes(type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)
                m_remove_conntrack.assert_called_once_with(set(), 4)

    @mock.patch("calico.felix.devices.remove_conntrack_flows", autospec=True)
    def test_set_routes_nothing_to_do(self, m_remove_conntrack):
        type = futils.IPV4
        ips = set(["1.2.3.4", "2.3.4.5"])
        retcode = futils.CommandOutput("", "")
        interface = "tapabcdef"
        mac = stub_utils.get_mac()
        with mock.patch('calico.felix.futils.check_call',
                        return_value=retcode):
            with mock.patch('calico.felix.devices.list_interface_ips',
                            return_value=ips):
                devices.set_routes(type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, 0)
                m_remove_conntrack.assert_called_once_with(set(), 4)

    @mock.patch("calico.felix.devices.remove_conntrack_flows", autospec=True)
    def test_set_routes_changed_ips(self, m_remove_conntrack):
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
            with mock.patch('calico.felix.devices.list_interface_ips',
                            return_value=current_ips):
                devices.set_routes(ip_type, ips, interface, mac)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)
                m_remove_conntrack.assert_called_once_with(set(["3.4.5.6"]), 4)

    @mock.patch("calico.felix.devices.remove_conntrack_flows", autospec=True)
    def test_set_routes_changed_ips_reset_arp(self, m_remove_conntrack):
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
            with mock.patch('calico.felix.devices.list_interface_ips',
                            return_value=current_ips):
                devices.set_routes(type, ips, interface, mac, reset_arp=True)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)
                m_remove_conntrack.assert_called_once_with(set(["3.4.5.6"]), 4)

    @mock.patch("calico.felix.devices.remove_conntrack_flows", autospec=True)
    def test_set_routes_add_ips(self, m_remove_conntrack):
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
            with mock.patch('calico.felix.devices.list_interface_ips',
                            return_value=current_ips):
                devices.set_routes(type, ips, interface, mac, reset_arp=True)
                self.assertEqual(futils.check_call.call_count, len(calls))
                futils.check_call.assert_has_calls(calls, any_order=True)
                m_remove_conntrack.assert_called_once_with(set(), 4)

    def test_list_interface_ips(self):
        type = futils.IPV4
        tap = "tap" + str(uuid.uuid4())[:11]

        retcode = futils.CommandOutput("", "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertFalse(ips)

        stdout = "10.11.9.90  scope link"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["10.11.9.90"]))

        stdout = "10.11.9.90  scope link\nblah-di-blah not valid\nx\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["10.11.9.90"]))

        type = futils.IPV6
        stdout = "2001:: scope link\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_ips(type, tap)
            futils.check_call.assert_called_once_with(["ip", "-6", "route", "list", "dev", tap])
            self.assertEqual(ips, set(["2001::"]))

        stdout = "2001:: scope link\n\n"
        retcode = futils.CommandOutput(stdout, "")
        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ips = devices.list_interface_ips(type, tap)
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

    def test_interface_up1(self):
        """
        Test that interface_up returns True when an interface is up.
        """
        tap = "tap" + str(uuid.uuid4())[:11]

        with mock.patch('__builtin__.open') as open_mock:
            open_mock.return_value = mock.MagicMock(spec=file)
            file_handle = open_mock.return_value.__enter__.return_value
            file_handle.read.return_value = '0x1003\n'

            is_up = devices.interface_up(tap)

            open_mock.assert_called_with(
                '/sys/class/net/%s/flags' % tap, 'r'
            )
            self.assertTrue(file_handle.read.called)
            self.assertTrue(is_up)

    def test_interface_up2(self):
        """
        Test that interface_up returns False when an interface is down.
        """
        tap = "tap" + str(uuid.uuid4())[:11]

        with mock.patch('__builtin__.open') as open_mock:
            open_mock.return_value = mock.MagicMock(spec=file)
            file_handle = open_mock.return_value.__enter__.return_value
            file_handle.read.return_value = '0x1002\n'

            is_up = devices.interface_up(tap)

            open_mock.assert_called_with(
                '/sys/class/net/%s/flags' % tap, 'r'
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
