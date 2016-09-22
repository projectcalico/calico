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
felix.test.test_config
~~~~~~~~~~~

Top level tests for Felix configuration.
"""

import logging
import re
import mock
import socket
import sys
from contextlib import nested
from calico.felix.config import Config, ConfigException
from calico.felix.test.base import load_config

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

# Logger
log = logging.getLogger(__name__)


class TestConfig(unittest.TestCase):
    def setUp(self):
        super(TestConfig, self).setUp()

        self.ghbn_patch = mock.patch("socket.gethostbyname", autospec=True)
        self.m_gethostbyname = self.ghbn_patch.start()
        self.m_gethostbyname.side_effect = self.dummy_gethostbyname
        self.compl_log_patch = mock.patch("calico.common.complete_logging",
                                          autospec=True)
        self.compl_log_patch.start()

    def dummy_gethostbyname(self, host):
        if host in ("localhost", "127.0.0.1"):
            return "127.0.0.1"
        elif re.match(r"\d+\.\d+\.\d+\.\d+", host):
            return host
        else:
            raise socket.gaierror("Dummy test error")

    def tearDown(self):
        self.compl_log_patch.stop()
        self.ghbn_patch.stop()
        super(TestConfig, self).tearDown()

    def test_default_config(self):
        """
        Test various ways of defaulting config.
        """
        files = [ "felix_missing.cfg", # does not exist
                  "felix_empty.cfg", # empty file
                  "felix_empty_section.cfg", # file with empty section
                  "felix_extra.cfg", # extra config is just logged
                  ]

        for filename in files:

            host_dict = { "InterfacePrefix": "blah",
                          "MetadataPort": 123 }
            global_dict = { "InterfacePrefix": "overridden",
                            "MetadataAddr": "1.2.3.4" }
            config = load_config(filename,
                                 host_dict=host_dict,
                                 global_dict=global_dict)

            # Test defaulting.
            self.assertEqual(config.ETCD_ADDRS, ["localhost:4001"])
            self.assertEqual(config.ETCD_SCHEME, "http")
            self.assertEqual(config.ETCD_KEY_FILE, None)
            self.assertEqual(config.ETCD_CERT_FILE, None)
            self.assertEqual(config.ETCD_CA_FILE,
                             "/etc/ssl/certs/ca-certificates.crt")
            self.assertEqual(config.HOSTNAME, socket.gethostname())
            self.assertEqual(config.IFACE_PREFIX, ["blah"])
            self.assertEqual(config.METADATA_PORT, 123)
            self.assertEqual(config.METADATA_IP, "1.2.3.4")
            self.assertEqual(config.REPORTING_INTERVAL_SECS, 30)
            self.assertEqual(config.REPORTING_TTL_SECS, 90)
            self.assertEqual(config.IPTABLES_MARK_MASK, 0xff000000)
            self.assertEqual(config.IPTABLES_MARK_ACCEPT, "0x1000000")
            self.assertEqual(config.IPV6_SUPPORT, "auto")

    def test_bad_plugin_name(self):
        env_dict = {"FELIX_IPTABLESGENERATORPLUGIN": "unknown"}
        with self.assertRaisesRegexp(ImportError,
                                     'No plugin called "unknown" has been '
                                     'registered for entrypoint '
                                     '"calico.felix.iptables_generator".'):
            config = load_config("felix_default.cfg", env_dict=env_dict)

    def test_bad_ipv6_support_value(self):
        env_dict = {"FELIX_IPV6SUPPORT": "badvalue"}
        config = load_config("felix_default.cfg", env_dict=env_dict)
        self.assertEqual(config.IPV6_SUPPORT, "auto")

    def test_invalid_port(self):
        data = { "felix_invalid_port.cfg": "Invalid port in field",
                 "felix_invalid_addr.cfg": "Invalid or unresolvable",
                 "felix_invalid_both.cfg": "Invalid or unresolvable",
                 "felix_invalid_format.cfg": "Invalid format for field"
        }

        for filename in data:
            log.debug("Test filename : %s", filename)
            with self.assertRaisesRegexp(ConfigException,
                                         data[filename]):
                config = Config("calico/felix/test/data/%s" % filename)

    def test_invalid_action(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid field value"):
            config = Config("calico/felix/test/data/felix_invalid_action.cfg")

    def test_etcd_endpoints(self):
        env_dict = { "FELIX_ETCDENDPOINTS": "http://localhost:1, http://localhost:2,http://localhost:3 "}
        conf = load_config("felix_default.cfg", env_dict=env_dict)
        self.assertEqual(conf.ETCD_ADDRS, ["localhost:1", "localhost:2", "localhost:3"])
        self.assertEqual(conf.ETCD_SCHEME, "http")

    def test_etcd_endpoints_inconsistent_protocols(self):
        env_dict = { "FELIX_ETCDENDPOINTS": "https://a:1, http://b:2,http://c:3 "}
        with self.assertRaisesRegexp(ConfigException,
                                     "Inconsistent protocols in EtcdEndpoints"):
            conf = load_config("felix_default.cfg", env_dict=env_dict)

    def test_etcd_endpoints_format(self):
        env_dict = { "FELIX_ETCDENDPOINTS": "https://a:1, b:2"}
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid format of EtcdEndpoints"):
            conf = load_config("felix_default.cfg", env_dict=env_dict)

    def test_invalid_etcd(self):
        """
        Test that etcd validation works correctly.
        """
        data = {
            "felix_invalid_scheme.cfg": "Invalid protocol scheme",
            "felix_missing_key.cfg": "Missing etcd key",
            "felix_missing_cert.cfg": "Missing etcd certificate"
        }

        for filename in data:
            log.debug("Test filename : %s", filename)
            with self.assertRaisesRegexp(ConfigException,
                                         data[filename]):
                config = Config("calico/felix/test/data/%s" % filename)

    def test_unreadable_etcd_key(self):
        """
        Test that we throw an exception when the etcd key is unreadable
        """
        with nested(mock.patch("os.path.isfile", autospec=True),
                    mock.patch("os.access", autospec=True)) \
             as (m_isfile, m_access):

            m_isfile.return_value = True
            m_access.return_value = False
            with self.assertRaisesRegexp(ConfigException,
                                         "Cannot read key file"):
                config = Config("calico/felix/test/data/felix_unreadable_key.cfg")

    def test_unreadable_etcd_cert(self):
        """
        Test that we throw an exception when the etcd cert is unreadable
        """
        with nested(mock.patch("os.path.isfile", autospec=True),
                    mock.patch("os.access", autospec=True)) \
             as (m_isfile, m_access):

            m_isfile.return_value = True
            m_access.side_effect = iter([True, False])
            with self.assertRaisesRegexp(ConfigException,
                                         "Cannot read cert file"):
                config = Config("calico/felix/test/data/felix_unreadable_cert.cfg")

    def test_unreadable_etcd_ca(self):
        """
        Test that we throw an exception when the etcd CA cert is unreadable
        """
        with nested(mock.patch("os.path.isfile", autospec=True),
                    mock.patch("os.access", autospec=True)) \
             as (m_isfile, m_access):

            m_isfile.return_value = True
            m_access.side_effect = iter([True, True, False])
            with self.assertRaisesRegexp(ConfigException,
                                         "Missing CA certificate"):
                config = Config("calico/felix/test/data/felix_unreadable_ca.cfg")

    def test_none_ca(self):
        """
        Test that the CA can be overriden to None.
        """
        with nested(mock.patch("os.path.isfile", autospec=True),
                    mock.patch("os.access", autospec=True)) \
             as (m_isfile, m_access):

            m_isfile.return_value = True
            m_access.return_value = True
            config = load_config("felix_none_ca.cfg")
            self.assertEqual(config.ETCD_CA_FILE, None)

    def test_no_logfile(self):
        # Logging to file can be excluded by explicitly saying "none" -
        # but if in etcd config the file is still created.
        cfg_dict = { "InterfacePrefix": "blah",
                     "LogFilePath": "None" }
        config = load_config("felix_missing.cfg",
                             host_dict=cfg_dict)

        self.assertEqual(config.LOGFILE, None)

        cfg_dict = { "InterfacePrefix": "blah"}
        config = load_config("felix_nolog.cfg",
                             host_dict=cfg_dict)

        self.assertEqual(config.LOGFILE, None)
        self.assertEqual(config.DRIVERLOGFILE, None)

    def test_no_metadata(self):
        # Metadata can be excluded by explicitly saying "none"

        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "NoNe",
                     "MetadataPort": 123 }

        config = load_config("felix_missing.cfg",
                             host_dict=cfg_dict)

        # Test defaulting.
        self.assertEqual(config.METADATA_IP, None)
        self.assertEqual(config.METADATA_PORT, None)

    def test_metadata_port_not_int(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "127.0.0.1",
                     "MetadataPort": "bloop" }

        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*MetadataPort"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_metadata_port_not_valid_1(self):
        for i in (0, -1, 99999):
            log.debug("Test invalid metadata port %d", i)
            cfg_dict = { "InterfacePrefix": "blah",
                         "MetadataAddr": "127.0.0.1",
                         "MetadataPort": i }
            with self.assertRaisesRegexp(ConfigException,
                                         "Invalid field value.*MetadataPort"):
                load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_bad_metadata_addr(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "bloop",
                     "MetadataPort": "123" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable.*MetadataAddr"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.m_gethostbyname.assert_has_calls([mock.call("bloop")])

    def test_bad_ipip_addr(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "IpInIpTunnelAddr": "bloop"}
        with self.assertRaisesRegexp(
                ConfigException,
                "Invalid or unresolvable.*IpInIpTunnelAddr"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.m_gethostbyname.assert_has_calls([mock.call("bloop")])

    def test_none_string_ipip_addr(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "IpInIpTunnelAddr": "none"}
        conf = load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.assertEqual(conf.IP_IN_IP_ADDR, None)

    def test_none_ipip_addr(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "IpInIpTunnelAddr": None}
        conf = load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.assertEqual(conf.IP_IN_IP_ADDR, None)

    def test_bad_log_level(self):
        for field in ("LogSeverityFile", "LogSeverityScreen", "LogSeveritySys"):
            cfg_dict = { "LogInterfacePrefix": "blah",
                         field: "bloop" }
            with self.assertRaisesRegexp(ConfigException,
                                         "Invalid log level.*%s" % field):
                load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_blank_metadata_addr(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "",
                     "MetadataPort": "123" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Blank value.*MetadataAddr"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_no_iface_prefix(self):
        config = load_config("felix_missing.cfg", host_dict={})
        self.assertEqual(config.IFACE_PREFIX, ["cali"])

    def test_file_sections(self):
        """
        Test various ways of defaulting config.
        """
        files = [
            "felix_section.cfg",  # lots of sections
        ]

        for filename in files:
            config = load_config(filename)

            # Test that read ignoring sections.
            self.assertEqual(config.ETCD_ADDRS, ["localhost:4001"])
            self.assertEqual(config.HOSTNAME, socket.gethostname())
            self.assertEqual(config.LOGFILE, "/log/nowhere.log")
            self.assertEqual(config.IFACE_PREFIX, ["whatever"])
            self.assertEqual(config.METADATA_PORT, 246)
            self.assertEqual(config.METADATA_IP, "1.2.3.4")
            self.assertEqual(config.REPORTING_INTERVAL_SECS, 5)
            self.assertEqual(config.REPORTING_TTL_SECS, 11)

    def test_upper_case_section(self):
        config = load_config("felix_default_section.cfg")
        self.assertEqual(config.ETCD_ADDRS, ["192.168.15.7:2379"])

    def test_env_var_override(self):
        """
        Test environment variables override config options.
        """
        env_dict = {"FELIX_ETCDADDR": "9.9.9.9:1234",
                    "FELIX_METADATAPORT": "999",
                    "FELIX_REPORTINGTTLSECS": "30",
                    "FELIX_REPORTINGINTERVALSECS": "10"}

        host_dict = { "InterfacePrefix": "blah",
                      "StartupCleanupDelay": "42",
                      "MetadataAddr": "4.3.2.1",
                      "MetadataPort": "123",
                      "ReportingIntervalSecs": "17",
                      "ReportingTTLSecs": "20"}

        global_dict = { "InterfacePrefix": "blah",
                        "StartupCleanupDelay": "99",
                        "MetadataAddr": "5.4.3.2",
                        "MetadataPort": "123",
                        "ReportingIntervalSecs": "13",
                        "ReportingTTLSecs": "25"}

        config = load_config("felix_section.cfg",
                             env_dict=env_dict,
                             global_dict=global_dict,
                             host_dict=host_dict)

        self.assertEqual(config.ETCD_ADDRS, ["9.9.9.9:1234"])
        self.assertEqual(config.HOSTNAME, socket.gethostname())
        self.assertEqual(config.LOGFILE, "/log/nowhere.log")
        self.assertEqual(config.IFACE_PREFIX, ["whatever"])
        self.assertEqual(config.METADATA_PORT, 999)
        self.assertEqual(config.METADATA_IP, "1.2.3.4")
        self.assertEqual(config.STARTUP_CLEANUP_DELAY, 42)
        self.assertEqual(config.REPORTING_INTERVAL_SECS, 10)
        self.assertEqual(config.REPORTING_TTL_SECS, 30)

    def test_ip_in_ip_enabled(self):
        test_values = [
            ("true", True),
            ("t", True),
            ("True", True),
            ("1", True),
            (1, True),
            ("yes", True),
            ("y", True),
            ("false", False),
            ("f", False),
            ("False", False),
            ("0", False),
            (0, False),
            ("no", False),
            ("n", False),
        ]
        for value, expected in test_values:
            cfg_dict = { "InterfacePrefix": "blah",
                         "IpInIpEnabled": value }
            config = load_config("felix_missing.cfg", host_dict=cfg_dict)
            self.assertEqual(config.IP_IN_IP_ENABLED, expected,
                             "%r was mis-interpreted as %r" %
                             (value, config.IP_IN_IP_ENABLED))

    def test_ip_in_ip_enabled_bad(self):
        cfg_dict = { "InterfacePrefix": "blah",
                     "IpInIpEnabled": "blah" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not a valid Boolean"
                                     ".*IpInIpEnabled"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_reporting_ttl_not_int(self):
        """
        Test exception is raised if status report ttl has invalid (non-integer) value.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingTTLSecs": "NaN"}
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_reporting_interval_not_int(self):
        """
        Test exception is raised if status reporting interval is invalid.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": "NaN"}
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*"):
            load_config("felix_missing.cfg", host_dict=cfg_dict)

    def test_negative_reporting_interval(self):
        """
        Test that status reporting is disabled if interval time is negative.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": -42,
                     "ReportingTTLSecs": 7 }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 0)
        self.assertEqual(config.REPORTING_TTL_SECS, 0)

    def test_insufficient_mark_bits(self):
        """
        Test that the mark masks are defaulted when there are insufficient
        bits.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "IptablesMarkMask": "0" }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.IPTABLES_MARK_MASK, 0xff000000)
        self.assertEqual(config.IPTABLES_MARK_ACCEPT, "0x1000000")
        self.assertEqual(config.IPTABLES_MARK_NEXT_TIER, "0x2000000")
        self.assertEqual(config.IPTABLES_MARK_ENDPOINTS, "0x4000000")

    def test_exact_mark_bits(self):
        """
        Test that the IptablesMarkMask works when the minimum number of bits is
        provided.
        """
        # This test is intended to catch if _validate_cfg() isn't updated when
        # new mark bits are added.
        cfg_dict = {"InterfacePrefix": "blah",
                    "IptablesMarkMask": "28"}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.IPTABLES_MARK_MASK, 0x0000001c)
        self.assertEqual(config.IPTABLES_MARK_ACCEPT, "0x4")
        self.assertEqual(config.IPTABLES_MARK_NEXT_TIER, "0x8")
        self.assertEqual(config.IPTABLES_MARK_ENDPOINTS, "0x10")

    def test_too_many_mark_bits(self):
        """
        Test that the mark masks are defaulted when the option is out of range.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "IptablesMarkMask": "9876543210" }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.IPTABLES_MARK_MASK, 0xff000000)
        self.assertEqual(config.IPTABLES_MARK_ACCEPT, "0x1000000")
        self.assertEqual(config.IPTABLES_MARK_NEXT_TIER, "0x2000000")
        self.assertEqual(config.IPTABLES_MARK_ENDPOINTS, "0x4000000")

    def test_hex_mark(self):
        """
        Test that the IptablesMarkMask accepts hexadecimal values.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "IptablesMarkMask": "0xe0" }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.IPTABLES_MARK_MASK, 0x000000e0)
        self.assertEqual(config.IPTABLES_MARK_ACCEPT, "0x20")
        self.assertEqual(config.IPTABLES_MARK_NEXT_TIER, "0x40")
        self.assertEqual(config.IPTABLES_MARK_ENDPOINTS, "0x80")

    def test_default_ttl(self):
        """
        Test that ttl is defaulted to at least 2.5 times the reporting
        interval.
        """
        cfg_dict = {
            "InterfacePrefix": "blah",
            "ReportingIntervalSecs": "21",
            "ReportingTTLSecs": "21",
        }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.REPORTING_TTL_SECS, 52)

    def test_valid_interval_and_ttl(self):
        """
        Test valid reporting parameters are not changed.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 42,
                     "ReportingTTLSecs": 47}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 42)
        self.assertEqual(config.REPORTING_TTL_SECS, 47)

    def test_reporting_interval_and_ttl_zero(self):
        """
        Test that zero reporting interval and ttl are passed correctly.
        """
        config = load_config
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 0,
                     "ReportingTTLSecs": 0}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 0)
        self.assertEqual(config.REPORTING_TTL_SECS, 0)

    def test_reporting_float(self):
        """
        Test that float reporting interval and ttl values are rounded down to integer.
        """
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 21.75,
                     "ReportingTTLSecs": 63.248}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 21)
        self.assertEqual(config.REPORTING_TTL_SECS, 63)

    def test_default_ipset_size(self):
        """
        Test that ipset size is defaulted if out of range.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = {
            "InterfacePrefix": "blah",
            "MaxIpsetSize": "0",
        }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.MAX_IPSET_SIZE, 2**20)

    def test_host_if_poll_defaulted(self):
        """
        Test that the poll interval is defaulted if out-of-range
        """
        cfg_dict = {"InterfacePrefix": "blah",
                    "HostInterfacePollInterval": "-1"}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.HOST_IF_POLL_INTERVAL_SECS, 10)

    def test_prometheus_port_valid(self):
        cfg_dict = {"InterfacePrefix": "blah",
                    "PrometheusMetricsEnabled": True,
                    "PrometheusMetricsPort": 9123,
                    "EtcdDriverPrometheusMetricsPort": 9124}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.PROM_METRICS_PORT, 9123)
        self.assertEqual(config.PROM_METRICS_DRIVER_PORT, 9124)
        self.assertEqual(config.PROM_METRICS_ENABLED, True)

    def test_prometheus_port_invalid(self):
        cfg_dict = {"InterfacePrefix": "blah",
                    "PrometheusMetricsEnabled": False,
                    "PrometheusMetricsPort": -1,
                    "EtcdDriverPrometheusMetricsPort": 65536}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.PROM_METRICS_PORT, 9091)
        self.assertEqual(config.PROM_METRICS_DRIVER_PORT, 9092)
        self.assertEqual(config.PROM_METRICS_ENABLED, False)

    def test_prometheus_port_defaults(self):
        cfg_dict = {"InterfacePrefix": "blah"}
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)

        self.assertEqual(config.PROM_METRICS_PORT, 9091)
        self.assertEqual(config.PROM_METRICS_DRIVER_PORT, 9092)
        self.assertEqual(config.PROM_METRICS_ENABLED, False)

    def test_failsafe_ports_defaults(self):
        config = load_config("felix_missing.cfg", host_dict=None)
        self.assertEqual(config.FAILSAFE_INBOUND_PORTS, [22])
        self.assertEqual(config.FAILSAFE_OUTBOUND_PORTS,
                         [2379, 2380, 4001, 7001])

    def test_failsafe_ports(self):
        cfg_dict = {
            "FailsafeInboundHostPorts": "100 , 200",
            "FailsafeOutboundHostPorts": "300",
        }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.assertEqual(config.FAILSAFE_INBOUND_PORTS, [100, 200])
        self.assertEqual(config.FAILSAFE_OUTBOUND_PORTS, [300])

    def test_failsafe_ports_empty(self):
        cfg_dict = {
            "FailsafeInboundHostPorts": "",
            "FailsafeOutboundHostPorts": "400,500",
        }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.assertEqual(config.FAILSAFE_INBOUND_PORTS, [])
        self.assertEqual(config.FAILSAFE_OUTBOUND_PORTS, [400, 500])

    def test_failsafe_ports_bad(self):
        cfg_dict = {
            "FailsafeInboundHostPorts": "foo",
        }
        self.assertRaises(ConfigException, load_config,
                          "felix_missing.cfg", host_dict=cfg_dict)
        cfg_dict = {
            "FailsafeOutboundHostPorts": "foo",
        }
        self.assertRaises(ConfigException, load_config,
                          "felix_missing.cfg", host_dict=cfg_dict)

    def test_failsafe_ports_out_of_range(self):
        cfg_dict = {
            "FailsafeInboundHostPorts": "0",
        }
        self.assertRaises(ConfigException, load_config,
                          "felix_missing.cfg", host_dict=cfg_dict)
        cfg_dict = {
            "FailsafeOutboundHostPorts": "65536",
        }
        self.assertRaises(ConfigException, load_config,
                          "felix_missing.cfg", host_dict=cfg_dict)

    def test_drop_action_defaulting(self):
        cfg_dict = {
            "DropActionOverride": "foobar",
        }
        config = load_config("felix_missing.cfg", host_dict=cfg_dict)
        self.assertEqual(config.ACTION_ON_DROP, "DROP")

    def test_drop_valid(self):
        for value in ("DROP", "LOG-and-DROP", "ACCEPT", "LOG-and-ACCEPT"):
            cfg_dict = {
                "DropActionOverride": value,
            }
            config = load_config("felix_missing.cfg", host_dict=cfg_dict)
            self.assertEqual(config.ACTION_ON_DROP, value)

    def test_interface_prefix(self):
        cfg_dict = {"InterfacePrefix": "foo"}
        config = load_config("felix_interface_prefix.cfg",
                             host_dict=cfg_dict)
        self.assertEqual(config.IFACE_PREFIX, ['foo'])

        cfg_dict = {"InterfacePrefix": "foo,bar"}
        config = load_config("felix_interface_prefix.cfg",
                             host_dict=cfg_dict)
        self.assertEqual(config.IFACE_PREFIX, ['foo', 'bar'])
