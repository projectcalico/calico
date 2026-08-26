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

import networking_calico.common as common
from networking_calico.common import config


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

        Note that each test must use option names that no other test uses:
        oslo.log remembers the deprecation reports it has already made, for the
        lifetime of the process, and silently drops a repeat of one it has
        already logged.
        """
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

    def test_deprecation_warning_when_option_set(self):
        opts = [
            cfg.IntOpt(
                "resync_interval_secs",
                default=0,
                deprecated_for_removal=True,
                deprecated_reason="This option has no effect.",
            ),
        ]
        warnings = self._deprecation_warnings(opts, "resync_interval_secs = 60\n")
        self.assertEqual(len(warnings), 1)
        self.assertIn("resync_interval_secs", warnings[0])
        self.assertIn("deprecated for removal", warnings[0])

        # The reason is what tells the operator what to do instead, so it
        # needs to reach the log too.
        self.assertIn("This option has no effect.", warnings[0])

    def test_deprecation_warning_when_option_set_to_its_default(self):
        # oslo.config keys the warning off the option being present in the
        # operator's config, not off its value differing from the default, so
        # pinning it to the default still gets a warning.  That is what we
        # want: the option is still there to be cleaned up.
        opts = [
            cfg.IntOpt(
                "resync_max_interval_secs",
                default=0,
                deprecated_for_removal=True,
                deprecated_reason="This option has no effect.",
            ),
        ]
        warnings = self._deprecation_warnings(opts, "resync_max_interval_secs = 0\n")
        self.assertEqual(len(warnings), 1)
        self.assertIn("resync_max_interval_secs", warnings[0])

    def test_no_deprecation_warning_when_option_not_set(self):
        # The operator has already cleaned up their config, or never had the
        # option set in the first place; they must not be nagged.
        opts = [
            cfg.IntOpt(
                "unset_deprecated_option",
                default=0,
                deprecated_for_removal=True,
                deprecated_reason="This option has no effect.",
            ),
            cfg.IntOpt(
                "still_used_option",
                default=0,
            ),
        ]
        warnings = self._deprecation_warnings(opts, "still_used_option = 7\n")
        self.assertEqual(warnings, [])

    def test_deprecation_warning_for_every_option_set(self):
        # oslo.log's de-duplication of deprecation reports keys on the whole
        # message, and every option's message starts out identical, so check
        # that a second stale option doesn't get swallowed by the first.
        opts = [
            cfg.IntOpt(
                "stale_option_one",
                default=0,
                deprecated_for_removal=True,
                deprecated_reason="This option has no effect.",
            ),
            cfg.IntOpt(
                "live_option",
                default=0,
            ),
            cfg.IntOpt(
                "stale_option_two",
                default=0,
                deprecated_for_removal=True,
                deprecated_reason="This option has no effect.",
            ),
        ]
        warnings = self._deprecation_warnings(
            opts,
            "stale_option_one = 60\nlive_option = 7\nstale_option_two = 900\n",
        )
        self.assertEqual(len(warnings), 2)
        self.assertIn("stale_option_one", warnings[0])
        self.assertIn("stale_option_two", warnings[1])


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
