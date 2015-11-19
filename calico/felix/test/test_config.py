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
felix.test.test_config
~~~~~~~~~~~

Top level tests for Felix configuration.
"""

import logging
import re
import mock
import socket
import sys
from calico.felix.config import Config, ConfigException

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

    def dummy_gethostbyname(self, host):
        if host in ("localhost", "127.0.0.1"):
            return "127.0.0.1"
        elif re.match(r"\d+\.\d+\.\d+\.\d+", host):
            return host
        else:
            raise socket.gaierror("Dummy test error")

    def tearDown(self):
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
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/%s" % filename)
            host_dict = { "InterfacePrefix": "blah",
                          "MetadataPort": 123 }
            global_dict = { "InterfacePrefix": "overridden",
                            "MetadataAddr": "1.2.3.4" }
            with mock.patch('calico.common.complete_logging'):
                config.report_etcd_config(host_dict, global_dict)

            # Test defaulting.
            self.assertEqual(config.ETCD_ADDR, "localhost:4001")
            self.assertEqual(config.HOSTNAME, socket.gethostname())
            self.assertEqual(config.IFACE_PREFIX, "blah")
            self.assertEqual(config.METADATA_PORT, 123)
            self.assertEqual(config.METADATA_IP, "1.2.3.4")
            self.assertEqual(config.REPORTING_INTERVAL_SECS, 30)
            self.assertEqual(config.REPORTING_TTL_SECS, 90)

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

    def test_no_logfile(self):
        # Logging to file can be excluded by explicitly saying "none" -
        # but if in etcd config the file is still created.
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "LogFilePath": "None" }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.LOGFILE, None)

        config = Config("calico/felix/test/data/felix_nolog.cfg")
        cfg_dict = { "InterfacePrefix": "blah"}
        config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.LOGFILE, None)
        self.assertEqual(config.DRIVERLOGFILE, None)

    def test_no_metadata(self):
        # Metadata can be excluded by explicitly saying "none"
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")

        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "NoNe",
                     "MetadataPort": 123 }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        # Test defaulting.
        self.assertEqual(config.METADATA_IP, None)
        self.assertEqual(config.METADATA_PORT, None)

    def test_metadata_port_not_int(self):
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "127.0.0.1",
                     "MetadataPort": "bloop" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*MetadataPort"):
            config.report_etcd_config({}, cfg_dict)

    def test_metadata_port_not_valid_1(self):
        for i in (0, -1, 99999):
            log.debug("Test invalid metadata port %d", i)
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/felix_missing.cfg")
            cfg_dict = { "InterfacePrefix": "blah",
                         "MetadataAddr": "127.0.0.1",
                         "MetadataPort": i }
            with self.assertRaisesRegexp(ConfigException,
                                         "Invalid field value.*MetadataPort"):
                config.report_etcd_config({}, cfg_dict)

    def test_bad_metadata_addr(self):
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "bloop",
                     "MetadataPort": "123" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable.*MetadataAddr"):
            config.report_etcd_config({}, cfg_dict)
        self.m_gethostbyname.assert_has_calls([mock.call("bloop")])

    def test_bad_log_level(self):
        for field in ("LogSeverityFile", "LogSeverityScreen", "LogSeveritySys"):
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/felix_missing.cfg")

            cfg_dict = { "LogInterfacePrefix": "blah",
                         field: "bloop" }
            with self.assertRaisesRegexp(ConfigException,
                                         "Invalid log level.*%s" % field):
                config.report_etcd_config({}, cfg_dict)

    def test_blank_metadata_addr(self):
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "MetadataAddr": "",
                     "MetadataPort": "123" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Blank value.*MetadataAddr"):
            config.report_etcd_config({}, cfg_dict)

    def test_no_iface_prefix(self):
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = {}
        with self.assertRaisesRegexp(ConfigException,
                        "Missing undefaulted value.*InterfacePrefix"):
            config.report_etcd_config({}, cfg_dict)

    def test_file_sections(self):
        """
        Test various ways of defaulting config.
        """
        files = [ "felix_section.cfg", # lots of sections
                  ]

        for filename in files:
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/%s" % filename)

            # Test that read ignoring sections.
            self.assertEqual(config.ETCD_ADDR, "localhost:4001")
            self.assertEqual(config.HOSTNAME, socket.gethostname())
            self.assertEqual(config.LOGFILE, "/log/nowhere.log")
            self.assertEqual(config.IFACE_PREFIX, "whatever")
            self.assertEqual(config.METADATA_PORT, 246)
            self.assertEqual(config.METADATA_IP, "1.2.3.4")
            self.assertEqual(config.REPORTING_INTERVAL_SECS, 5)
            self.assertEqual(config.REPORTING_TTL_SECS, 11)

    def test_env_var_override(self):
        """
        Test environment variables override config options.
        """
        with mock.patch.dict("os.environ", {"FELIX_ETCDADDR": "9.9.9.9:1234",
                                            "FELIX_METADATAPORT": "999",
                                            "FELIX_REPORTINGTTLSECS": "30",
                                            "FELIX_REPORTINGINTERVALSECS": "10"}):
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/felix_section.cfg")

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
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config(host_dict, global_dict)

        self.assertEqual(config.ETCD_ADDR, "9.9.9.9:1234")
        self.assertEqual(config.HOSTNAME, socket.gethostname())
        self.assertEqual(config.LOGFILE, "/log/nowhere.log")
        self.assertEqual(config.IFACE_PREFIX, "whatever")
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
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/felix_missing.cfg")
                cfg_dict = { "InterfacePrefix": "blah",
                             "IpInIpEnabled": value }
                config.report_etcd_config({}, cfg_dict)
                self.assertEqual(config.IP_IN_IP_ENABLED, expected,
                                 "%r was mis-interpreted as %r" %
                                 (value, config.IP_IN_IP_ENABLED))

    def test_ip_in_ip_enabled_bad(self):
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "IpInIpEnabled": "blah" }
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not a valid Boolean"
                                     ".*IpInIpEnabled"):
            config.report_etcd_config({}, cfg_dict)

    def test_reporting_ttl_not_int(self):
        """
        Test exception is raised if status report ttl has invalid (non-integer) value.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingTTLSecs": "NaN"}
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*"):
            config.report_etcd_config({}, cfg_dict)

    def test_reporting_interval_not_int(self):
        """
        Test exception is raised if status reporting interval is invalid.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": "NaN"}
        with self.assertRaisesRegexp(ConfigException,
                                     "Field was not integer.*"):
            config.report_etcd_config({}, cfg_dict)

    def test_negative_reporting_interval(self):
        """
        Test that status reporting is disabled if interval time is negative.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": -42,
                     "ReportingTTLSecs": 7 }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 0)
        self.assertEqual(config.REPORTING_TTL_SECS, 0)

    def test_default_ttl(self):
        """
        Test that ttl is defaulted to at least 2.5 times the reporting
        interval.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = {
            "InterfacePrefix": "blah",
            "ReportingIntervalSecs": "21",
            "ReportingTTLSecs": "21",
        }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.REPORTING_TTL_SECS, 52)

    def test_valid_interval_and_ttl(self):
        """
        Test valid reporting parameters are not changed.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 42,
                     "ReportingTTLSecs": 47}
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 42)
        self.assertEqual(config.REPORTING_TTL_SECS, 47)

    def test_reporting_interval_and_ttl_zero(self):
        """
        Test that zero reporting interval and ttl are passed correctly.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 0,
                     "ReportingTTLSecs": 0}
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

        self.assertEqual(config.REPORTING_INTERVAL_SECS, 0)
        self.assertEqual(config.REPORTING_TTL_SECS, 0)

    def test_reporting_float(self):
        """
        Test that float reporting interval and ttl values are rounded down to integer.
        """
        with mock.patch('calico.common.complete_logging'):
            config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "ReportingIntervalSecs": 21.75,
                     "ReportingTTLSecs": 63.248}
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config({}, cfg_dict)

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
