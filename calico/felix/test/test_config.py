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

from collections import namedtuple
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

    def test_env_var_override(self):
        """
        Test environment variables override config options,
        """
        with mock.patch.dict("os.environ", {"FELIX_ETCDADDR": "9.9.9.9:1234",
                                            "FELIX_METADATAPORT": "999"}):
            with mock.patch('calico.common.complete_logging'):
                config = Config("calico/felix/test/data/felix_section.cfg")

        host_dict = { "InterfacePrefix": "blah",
                      "StartupCleanupDelay": "42",
                      "MetadataAddr": "4.3.2.1",
                      "MetadataPort": "123" }

        global_dict = { "InterfacePrefix": "blah",
                        "StartupCleanupDelay": "99",
                        "MetadataAddr": "5.4.3.2",
                        "MetadataPort": "123" }
        with mock.patch('calico.common.complete_logging'):
            config.report_etcd_config(host_dict, global_dict)

        self.assertEqual(config.ETCD_ADDR, "9.9.9.9:1234")
        self.assertEqual(config.HOSTNAME, socket.gethostname())
        self.assertEqual(config.LOGFILE, "/log/nowhere.log")
        self.assertEqual(config.IFACE_PREFIX, "whatever")
        self.assertEqual(config.METADATA_PORT, 999)
        self.assertEqual(config.METADATA_IP, "1.2.3.4")
        self.assertEqual(config.STARTUP_CLEANUP_DELAY, 42)
