# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
calico.tests.test_stats
~~~~~~~~~~~~~~~~~~~~~~~

Tests for stats gathering functions.
"""

import logging
from unittest import TestCase

from mock import patch

from calico.stats import RateStat, AggregateStat

_log = logging.getLogger(__name__)


class TestRateStat(TestCase):
    def setUp(self):
        super(TestRateStat, self).setUp()
        self.stat = RateStat("foo")

    def test_string_no_data(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.return_value = 1234
            self.stat.reset()
            self.assertEqual(str(self.stat), "foo: 0 in 0.0s (0.000/s)")

    def test_string_with_data_zero_time(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.return_value = 1234
            self.stat.reset()
            self.stat.store_occurence()
            self.stat.store_occurence()
            self.assertEqual(str(self.stat), "foo: 2 in 0.0s (0.000/s)")

    def test_string_with_data_and_time(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.side_effect = iter([1234, 1235, 1235])
            self.stat.reset()
            self.stat.store_occurence()
            self.stat.store_occurence()
            self.assertEqual(str(self.stat), "foo: 2 in 1.0s (2.000/s)")


class TestAggregateStat(TestCase):
    def setUp(self):
        super(TestAggregateStat, self).setUp()
        self.stat = AggregateStat("foo", "ms")

    def test_string_no_data(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.return_value = 1234
            self.stat.reset()
            self.assertEqual(
                str(self.stat),
                "foo: 0 in 0.0s (0.000/s) "
                "min=0.000ms mean=0.000ms max=0.000ms"
            )

    def test_string_with_data_zero_time(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.return_value = 1234
            self.stat.reset()
            self.stat.store_reading(123)
            self.stat.store_reading(124)
            self.assertEqual(
                str(self.stat),
                "foo: 2 in 0.0s (0.000/s) "
                "min=123.000ms mean=123.500ms max=124.000ms"
            )

    def test_string_with_data_and_time(self):
        with patch("calico.stats.monotonic_time", autospec=True) as m_time:
            m_time.side_effect = iter([1234, 1235, 1235])
            self.stat.reset()
            self.stat.store_reading(123)
            self.stat.store_reading(124)
            self.assertEqual(
                str(self.stat),
                "foo: 2 in 1.0s (2.000/s) "
                "min=123.000ms mean=123.500ms max=124.000ms"
            )
