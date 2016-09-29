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
calico.test.test_monotonic
~~~~~~~~~~~~~~~~~~~~~~~~~~

Test for monotonic clock functions.
"""
import logging
import time
from unittest import TestCase

from networking_calico.monotonic import monotonic_time

_log = logging.getLogger(__name__)


class TestMonotonic(TestCase):

    def test_mainline(self):
        a = monotonic_time()
        time.sleep(0.01)
        b = monotonic_time()
        self.assertTrue(b >= a + 0.01,
                        msg="Monotonic time did not increase as "
                        "expected: %s, %s" % (a, b))
