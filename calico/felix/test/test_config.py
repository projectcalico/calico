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
import sys
import unittest
from calico.felix.config import Config, ConfigException

class TestConfig(unittest.TestCase):
    def setUp(self):
        # Set up logging. For now, we just throw away any logs we get.
        log  = logging.getLogger("calico.felix")
        handler = logging.NullHandler()
        log.addHandler(handler)

    def test_simple_good_config(self):
        config = Config("calico/felix/test/data/felix_basic.cfg")
        self.assertEqual(config.PLUGIN_ADDR, "controller")

    def test_missing_section(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Section log missing from config file"):
            config = Config("calico/felix/test/data/felix_missing_section.cfg")

    def test_invalid_config(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "not defined in section"):
            config = Config("calico/felix/test/data/felix_invalid.cfg")

    def test_bad_dns_config(self):
        with self.assertRaisesRegexp(ConfigException, "Invalid MetadataAddr"):
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

if __name__ == "__main__":
    unittest.main()
