# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
calico.test.test_calcollections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test for collections library.
"""

import logging
from mock import Mock, call, patch

from calico.calcollections import SetDelta
from unittest2 import TestCase

_log = logging.getLogger(__name__)


class TestSetDelta(TestCase):
    def setUp(self):
        self.set = set("abc")
        self.delta = SetDelta(self.set)

    def test_add(self):
        self.delta.add("c")
        self.delta.add("d")
        # Only "d" added, "c" was already present.
        self.assertEqual(self.delta.added_entries, set(["d"]))
        # Now apply, should mutate the set.
        self.assertEqual(self.set, set("abc"))
        self.delta.apply_and_reset()
        self.assertEqual(self.set, set("abcd"))
        self.assertEqual(self.delta.added_entries, set())

    def test_remove(self):
        self.delta.remove("c")
        self.delta.remove("d")
        # Only "c" added, "d" was already missing.
        self.assertEqual(self.delta.removed_entries, set(["c"]))
        # Now apply, should mutate the set.
        self.assertEqual(self.set, set("abc"))
        self.delta.apply_and_reset()
        self.assertEqual(self.set, set("ab"))
        self.assertEqual(self.delta.removed_entries, set())

    def test_add_and_remove(self):
        self.delta.add("c")  # No-op, already present.
        self.delta.add("d")  # Put in added set.
        self.delta.add("e")  # Will remain in added set.
        self.delta.remove("c")  # Recorded in remove set.
        self.delta.remove("d")  # Cancels the pending add only.
        self.delta.remove("f")  # No-op.

        self.assertEqual(self.delta.added_entries, set("e"))
        self.assertEqual(self.delta.removed_entries, set("c"))
        self.delta.apply_and_reset()
        self.assertEqual(self.set, set("abe"))



