# -*- coding: utf-8 -*-
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

import logging
import os
import shutil
import tempfile
import unittest
from collections import namedtuple

import mock

from oslo_config import cfg
from oslo_log import versionutils

import networking_calico.common as common
from networking_calico.common import config
from networking_calico.plugins.ml2.drivers.calico.mech_calico import calico_opts


class _WarningCollector(logging.Handler):
    """Collects the messages that oslo.config logs at WARNING."""

    def __init__(self):
        super(_WarningCollector, self).__init__(level=logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class TestConfig(unittest.TestCase):

    def test_additional_options_registered(self):
        add_opt = cfg.StrOpt("test_option", default="test")
        config.register_options(cfg.CONF, additional_options=[add_opt])
        self.assertEqual(cfg.CONF["calico"]["test_option"], "test")

    def _deprecation_warnings(self, opts, conf_file_body):
        """Read the deprecated options in OPTS; return the warnings logged.

        OPTS are registered into a private ConfigOpts -- not the global
        cfg.CONF -- which is then populated from a neutron.conf whose [calico]
        section is CONF_FILE_BODY.

        oslo suppresses a repeated deprecation report in two separate places,
        and both outlive an individual test: oslo.log remembers the (message,
        args) pairs it has already logged, for the lifetime of the process, and
        each Opt latches its own ``_logged_deprecation``.  Because OPTS are the
        driver's real Opt objects, shared by every test here, that latch is
        still set from whichever test ran first -- which is enough to stop a
        later test observing any warning at all, and made the negative test
        below incapable of failing.  So reset both, and let each test start from
        a clean slate.
        """
        versionutils._deprecated_messages_sent.clear()
        for opt in opts:
            opt._logged_deprecation = False

        conf = cfg.ConfigOpts()
        conf.register_opts(opts, "calico")

        conf_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, conf_dir)
        conf_file = os.path.join(conf_dir, "neutron.conf")
        with open(conf_file, "w") as f:
            f.write("[calico]\n" + conf_file_body)
        conf(["--config-file", conf_file], project="neutron")

        collector = _WarningCollector()
        logger = logging.getLogger("oslo_config.cfg")
        old_level = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(collector)
        self.addCleanup(logger.setLevel, old_level)
        self.addCleanup(logger.removeHandler, collector)

        config.read_deprecated_options(conf, opts)
        return collector.messages

    def test_deprecation_warning_for_each_option_the_operator_set(self):
        # Both of the driver's deprecated options, one set to a non-default
        # value and the other pinned to its own default.  oslo.config keys the
        # warning off the option being present in the operator's config, not
        # off its value differing from the default, so both must warn -- the
        # 0 is still a setting the operator has to remove.
        warnings = self._deprecation_warnings(
            calico_opts,
            "resync_interval_secs = 60\nresync_max_interval_secs = 0\n",
        )

        # One warning each, in particular the second not swallowed by the
        # first: oslo.log de-duplicates deprecation reports on the message,
        # which starts out identical for every option.
        self.assertEqual(len(warnings), 2)
        logged = "\n".join(warnings)
        self.assertIn('"resync_interval_secs"', logged)
        self.assertIn('"resync_max_interval_secs"', logged)
        self.assertIn("deprecated for removal", logged)

        # Each option's own deprecated_reason is what tells the operator what
        # to do instead, so it needs to reach the log too.
        self.assertIn("calico-resync CLI", logged)

    def test_no_deprecation_warning_when_no_such_option_set(self):
        # The operator has already cleaned up their config, or never had these
        # options set in the first place; they must not be nagged.  The live
        # options they do set are read without complaint.
        warnings = self._deprecation_warnings(
            calico_opts,
            "startup_resync = never\nnum_port_status_threads = 8\n",
        )
        self.assertEqual(warnings, [])


Config = namedtuple("Config", ["IFACE_PREFIX", "HOSTNAME"])

# Logger
_log = logging.getLogger(__name__)


MISSING = object()


class TestCommon(unittest.TestCase):
    def setUp(self):
        self.m_config = mock.Mock()
        self.m_config.IFACE_PREFIX = ["tap"]
        self.m_config.HOSTNAME = "localhost"

    def tearDown(self):
        pass

    def test_validate_cidr(self):
        self.assertTrue(common.validate_cidr("1.2.3.4", 4))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 4))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", 4))
        self.assertTrue(common.validate_cidr("1.2.3", 4))
        self.assertFalse(common.validate_cidr("bloop", 4))
        self.assertFalse(common.validate_cidr("::", 4))
        self.assertFalse(common.validate_cidr("2001::abc", 4))
        self.assertFalse(common.validate_cidr("2001::a/64", 4))

        self.assertFalse(common.validate_cidr("1.2.3.4", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4/32", 6))
        self.assertFalse(common.validate_cidr("1.2.3", 6))
        self.assertFalse(common.validate_cidr("bloop", 6))
        self.assertTrue(common.validate_cidr("::", 6))
        self.assertTrue(common.validate_cidr("2001::abc", 6))
        self.assertTrue(common.validate_cidr("2001::a/64", 6))

        self.assertTrue(common.validate_cidr("1.2.3.4", None))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", None))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", None))
        self.assertTrue(common.validate_cidr("1.2.3", None))
        self.assertFalse(common.validate_cidr("bloop", None))
        self.assertTrue(common.validate_cidr("::", None))
        self.assertTrue(common.validate_cidr("2001::abc", None))
        self.assertTrue(common.validate_cidr("2001::a/64", None))

        self.assertFalse(common.validate_cidr(None, None))

    def test_validate_region(self):
        # Valid openstack_region.
        config._validate_region("region1")
        # openstack_region with uppercase.
        self.assertRaises(AssertionError, config._validate_region, "RegionOne")
        # openstack_region with slash.
        self.assertRaises(AssertionError, config._validate_region, "us/east")
        # openstack_region with underscore.
        self.assertRaises(AssertionError, config._validate_region, "my_region")
        # openstack_region too long.
        self.assertRaises(
            AssertionError,
            config._validate_region,
            "my-region-has-a-very-long-and-extremely-interesting-name",
        )
