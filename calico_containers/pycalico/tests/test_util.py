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
from subprocess import CalledProcessError, check_output
from pycalico.util import get_host_ips

MOCK_IP_ADDR = \
"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:73:c8:d0 brd ff:ff:ff:ff:ff:ff
    inet 172.24.114.18/24 brd 172.24.114.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2620:104:4008:69:8d7c:499f:2f04:9e55/64 scope global temporary dynamic 
       valid_lft 603690sec preferred_lft 84690sec
    inet6 2620:104:4008:69:a00:27ff:fe73:c8d0/64 scope global dynamic 
       valid_lft 604698sec preferred_lft 86298sec
    inet6 fe80::a00:27ff:fe73:c8d0/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 172.17.42.1/24 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::188f:d6ff:fe1f:1482/64 scope link 
       valid_lft forever preferred_lft forever
"""

MOCK_IP_ADDR_LOOPBACK = \
"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
"""


class TestUtil(unittest.TestCase):

  @patch("pycalico.util.check_output", autospec=True)
  def test_get_host_ips_standard(self, m_check_output):
    # Test IPv4
    m_check_output.return_value = MOCK_IP_ADDR
    addrs = get_host_ips(version=4)
    m_check_output.assert_called_once_with(["ip", "-4", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['172.24.114.18', '172.17.42.1'])

    # Test IPv6
    addrs = get_host_ips(version=6)
    m_check_output.assert_called_once_with(["ip", "-6", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                  'fe80::a00:27ff:fe73:c8d0',
                  'fe80::188f:d6ff:fe1f:1482'])

  @patch("pycalico.util.check_output", autospec=True)
  def test_get_host_ips_loopback_only(self, m_check_output):
    # Test Loopback
    m_check_output.return_value = MOCK_IP_ADDR_LOOPBACK
    addrs = get_host_ips(version=4)
    m_check_output.assert_called_once_with(["ip", "-4", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, [])

    addrs = get_host_ips(version=6)
    m_check_output.assert_called_once_with(["ip", "-6", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, [])

  @patch("pycalico.util.check_output", autospec=True)
  def test_get_host_ips_exclude(self, m_check_output):
    # Exclude "docker0"
    m_check_output.return_value = MOCK_IP_ADDR
    addrs = get_host_ips(version=4, exclude=["docker0"])
    m_check_output.assert_called_once_with(["ip", "-4", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['172.24.114.18'])

    addrs = get_host_ips(version=6, exclude=["docker0"])
    m_check_output.assert_called_once_with(["ip", "-6", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                  'fe80::a00:27ff:fe73:c8d0'])

    # Exclude empty list
    addrs = get_host_ips(version=4, exclude=[""])
    m_check_output.assert_called_once_with(["ip", "-4", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['172.24.114.18', '172.17.42.1'])

    addrs = get_host_ips(version=6, exclude=[""])
    m_check_output.assert_called_once_with(["ip", "-6", "addr"])
    m_check_output.reset_mock()
    self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                  'fe80::a00:27ff:fe73:c8d0',
                  'fe80::188f:d6ff:fe1f:1482'])

  @patch("pycalico.util.check_output", autospec=True)
  def test_get_host_ips_fail_check_output(self, m_check_output):
    m_check_output.side_effect = CalledProcessError(returncode=1, cmd=check_output(["ip", "-4", "addr"]))
    with self.assertRaises(SystemExit):
        addrs = get_host_ips(version=4)
