# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
import socket
import sys
import unittest
from calico.felix.config import Config, ConfigException

# Logger
log = logging.getLogger(__name__)

class TestConfig(unittest.TestCase):
    def setUp(self):
        pass

    def test_simple_good_config(self):
        config = Config("calico/felix/test/data/felix_basic.cfg")
        self.assertEqual(config.PLUGIN_ADDR, "localhost")
        # We did not explicitly set HOSTNAME in this config - check defaulting.
        self.assertEqual(config.HOSTNAME, socket.gethostname())

    def test_missing_section(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Section log missing from config file"):
            config = Config("calico/felix/test/data/felix_missing_section.cfg")

    def test_invalid_config(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "not defined in section"):
            config = Config("calico/felix/test/data/felix_invalid.cfg")

    def test_bad_dns_config(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable MetadataAddr"):
            config = Config("calico/felix/test/data/felix_bad_dns.cfg")

    def test_bad_port_config(self):
        with self.assertRaisesRegexp(ConfigException, "Invalid MetadataPort"):
            config = Config("calico/felix/test/data/felix_bad_port.cfg")

    def test_extra_config(self):
        # Extra data is not an error, but does log.
        config = Config("calico/felix/test/data/felix_extra.cfg")

    def test_no_metadata(self):
        # Not an error.
        config = Config("calico/felix/test/data/felix_no_metadata.cfg")
        self.assertEqual(config.METADATA_IP, None)
        self.assertEqual(config.METADATA_PORT, None)

    def test_blank_plugin(self):
        with self.assertRaisesRegexp(ConfigException, "Blank PluginAddr"):
            config = Config("calico/felix/test/data/felix_blank_plugin.cfg")

    def test_invalid_acl(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable ACLAddr"):
            config = Config("calico/felix/test/data/felix_invalid_acl.cfg")

    def test_localaddr_all(self):
        # Not an error.
        config = Config("calico/felix/test/data/felix_localaddr_all.cfg")
        self.assertEqual(config.LOCAL_ADDR, "*")

    def test_localaddr_specific(self):
        # Not an error.
        config = Config("calico/felix/test/data/felix_localaddr_specific.cfg")
        self.assertEqual(config.LOCAL_ADDR, "1.2.3.4")

    def test_localaddr_host(self):
        # Not an error.
        config = Config("calico/felix/test/data/felix_localaddr_host.cfg")
        self.assertIn("127.", config.LOCAL_ADDR)

    def test_bad_localaddr(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable LocalAddress"):
            config = Config("calico/felix/test/data/felix_bad_localaddr.cfg")

    def test_nologfile(self):
        config = Config("calico/felix/test/data/felix_nologfile.cfg")
        self.assertIs(config.LOGFILE, None)

    def test_nologfile2(self):
        config = Config("calico/felix/test/data/felix_nologfile2.cfg")
        self.assertIs(config.LOGFILE, None)

