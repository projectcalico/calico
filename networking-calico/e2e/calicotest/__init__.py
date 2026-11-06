# -*- coding: utf-8 -*-
# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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
calicotest
~~~~~~~~

This module contains Calico/OpenStack e2e tests.
"""

import logging
from logging import handlers
import os
from unittest import TestCase, TestSuite
from unittest.loader import _FailedTest

FORMAT = "%(asctime)s [%(levelname)s][%(process)s] %(name)s %(lineno)d: %(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT)
logging.getLogger("paramiko").setLevel(logging.WARNING)

formatter = logging.Formatter(FORMAT)
handler = handlers.WatchedFileHandler("test.log")
handler.setFormatter(formatter)
logging.root.addHandler(handler)


def load_tests(loader, tests, pattern):
    logging.info("load_tests: loader=%r", loader)
    logging.info("load_tests: tests=%r", tests)
    logging.info("load_tests: pattern=%r", pattern)
    logging.info("load_tests: cwd=%r", os.getcwd())
    test_suite = loader.discover(
        os.path.join(os.getcwd(), "calicotest", "openstack"), pattern
    )

    def iter_ts(r, prefix, filter, filtered_suite):
        for item in r:
            if isinstance(item, TestSuite):
                if list(item):
                    logging.info("load_tests: %sTestSuite", prefix)
                    iter_ts(item, prefix + " ", filter, filtered_suite)
            elif isinstance(item, _FailedTest):
                # A module that failed to import, or similar.  It has no filter
                # attributes, so would otherwise be silently dropped; keep it so that
                # the failure is reported.
                logging.info("load_tests: %sFAILED: %r", prefix, item)
                filtered_suite.addTest(item)
            elif isinstance(item, TestCase):
                logging.info("load_tests: %s%r", prefix, item)
                cls = item.__class__
                method = getattr(item, item._testMethodName)
                filter_settings = {}
                for filter_attribute_name in ["fv_test", "unit_test"]:
                    filter_settings[filter_attribute_name] = getattr(
                        cls,
                        filter_attribute_name,
                        False,
                    )

                    # Also allow specification on a per-method basis.  When
                    # that is the case it overrides the class-level setting.
                    method_setting = getattr(method, filter_attribute_name, None)
                    if method_setting is not None:
                        logging.info(
                            "load_tests: %s%s says %s %s",
                            prefix,
                            item._testMethodName,
                            filter_attribute_name,
                            method_setting,
                        )
                        filter_settings[filter_attribute_name] = method_setting

                logging.info("load_tests: %s%s", prefix, filter_settings)

                if eval(filter, filter_settings):
                    logging.info("load_tests: %sincluded", prefix)
                    filtered_suite.addTest(item)
            else:
                logging.info("load_tests: %sERROR: %r", prefix, item)

    filter = os.getenv("TEST_FILTER")
    if filter:
        filtered_suite = TestSuite()
        iter_ts(test_suite, "", filter, filtered_suite)
        return filtered_suite

    return test_suite
