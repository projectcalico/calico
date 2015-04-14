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
import etcd
import logging
from mock import patch
import socket
import sys
from calico.felix.config import Config, ConfigException
from calico.felix.fetcd import EtcdWatcher

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

real_client = etcd.client

# Logger
log = logging.getLogger(__name__)

# Set of results from etcd.
etcd_results = {}

EtcdChild = namedtuple('EtcdChild', ['key', 'value'])

class StubEtcdResult(object):
    def __init__(self, path):
        self.children = []
        self.path = path
        etcd_results[path] = self

    def add_child(self, key, value):
        key = "%s/%s" % (self.path, key)
        self.children.append(EtcdChild(key, value))

class StubEtcd(object):
    """
    Trivial etcd stub.
    """
    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port

    def read(self, path, timeout=None):
        return etcd_results[path]


class TestConfig(unittest.TestCase):
    def setUp(self):
        # Stub out etcd.
        etcd.Client = StubEtcd
        etcd_results.clear()

    def tearDown(self):
        # Unstub etcd.
        etcd.Client = real_client

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
            host = socket.gethostname()
            host_path = "/calico/host/%s/config/" % host


            config = Config("calico/felix/test/data/%s" % filename)
            cfg_dict = { "InterfacePrefix": "blah",
                         "ExtraJunk": "whatever", #ignored
                         "ResyncIntervalSecs": "123" }
            config.update_config(cfg_dict)

            # Test defaulting.
            self.assertEqual(config.ETCD_ADDR, "localhost:4001")
            self.assertEqual(config.HOSTNAME, host)
            self.assertEqual(config.IFACE_PREFIX, "blah")
            self.assertEqual(config.RESYNC_INT_SEC, 123)

    def test_invalid_port(self):

        data = { "felix_invalid_port.cfg": "Invalid port in EtcdAddr",
                 "felix_invalid_addr.cfg": "Invalid or unresolvable EtcdAddr",
                 "felix_invalid_both.cfg": "Invalid or unresolvable EtcdAddr",
                 "felix_invalid_format.cfg": "Invalid format for EtcdAddr"
        }


        for filename in data:
            log.debug("Test filename : %s", filename)
            with self.assertRaisesRegexp(ConfigException,
                                         data[filename]):
                config = Config("calico/felix/test/data/%s" % filename)

    def test_no_logfile(self):
        # Logging to file can be excluded by explicitly saying "none"
        host = socket.gethostname()
        host_path = "/calico/host/%s/config/" % host

        result = StubEtcdResult("/calico/config/")
        result.add_child("InterfacePrefix", "blah")
        result.add_child("LogFilePath", "NoNe")

        result = StubEtcdResult(host_path)

        config = Config("calico/felix/test/data/felix_missing.cfg")
        cfg_dict = { "InterfacePrefix": "blah",
                     "LogFilePath": "None",
                     "ResyncIntervalSecs": "123" }
        config.update_config(cfg_dict)

        self.assertEqual(config.LOGFILE, None)

    def xtest_no_metadata(self):
        # Metadata can be excluded by explicitly saying "none"
        host = socket.gethostname()
        host_path = "/calico/host/%s/config/" % host

        result = StubEtcdResult("/calico/config/")
        result.add_child("InterfacePrefix", "blah")
        result.add_child("MetadataAddr", "NoNe")
        result.add_child("MetadataPort", "123")

        result = StubEtcdResult(host_path)

        config = Config("calico/felix/test/data/felix_missing.cfg")
        etcd_watcher = EtcdWatcher(config)
        result = etcd_watcher.load_config(async=True)
        result.get()

        # Test defaulting.
        self.assertEqual(config.METADATA_IP, None)
        self.assertEqual(config.METADATA_PORT, None)

    def xtest_bad_metadata_port(self):
        with self.assertRaisesRegexp(ConfigException, "Invalid MetadataPort"):
            host = socket.gethostname()
            host_path = "/calico/host/%s/config/" % host

            result = StubEtcdResult("/calico/config/")
            result.add_child("InterfacePrefix", "blah")
            result.add_child("MetadataPort", "bloop")

            result = StubEtcdResult(host_path)

            config = Config("calico/felix/test/data/felix_missing.cfg")
            etcd_watcher = EtcdWatcher(config)
            result = etcd_watcher.load_config(async=True)
            result.get()

    def xtest_bad_metadata_addr(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Invalid or unresolvable MetadataAddr"):
            host = socket.gethostname()
            host_path = "/calico/host/%s/config/" % host

            result = StubEtcdResult("/calico/config/")
            result.add_child("InterfacePrefix", "blah")
            result.add_child("MetadataAddr", "bloop")

            result = StubEtcdResult(host_path)

            config = Config("calico/felix/test/data/felix_missing.cfg")
            etcd_watcher = EtcdWatcher(config)
            result = etcd_watcher.load_config(async=True)
            result.get()

    def xtest_blank_metadata_addr(self):
        with self.assertRaisesRegexp(ConfigException,
                                     "Blank MetadataAddr value"):
            host = socket.gethostname()
            host_path = "/calico/host/%s/config/" % host

            result = StubEtcdResult("/calico/config/")
            result.add_child("InterfacePrefix", "blah")
            result.add_child("MetadataAddr", "")

            result = StubEtcdResult(host_path)

            config = Config("calico/felix/test/data/felix_missing.cfg")
            etcd_watcher = EtcdWatcher(config)
            result = etcd_watcher.load_config(async=True)
            result.get()


    def xtest_no_iface_prefix(self):
        with self.assertRaisesRegexp(ConfigException, "Missing InterfacePrefix"):
            host = socket.gethostname()
            host_path = "/calico/host/%s/config/" % host

            result = StubEtcdResult("/calico/config/")
            result = StubEtcdResult(host_path)

            config = Config("calico/felix/test/data/felix_missing.cfg")
            etcd_watcher = EtcdWatcher(config)
            result = etcd_watcher.load_config(async=True)
            result.get()


    @patch("ConfigParser.ConfigParser", autospec=True)
    def xtest_env_var_override(self, m_ConfigParser):
        """
        Test environment variables override config options,
        """
        with patch.dict("os.environ", {"FELIX_ETCDADDR": "testhost:1234"}):
            cfg = config.Config("/tmp/felix.cfg")
        self.assertEqual(cfg.ETCD_ADDR, "testhost:1234")
