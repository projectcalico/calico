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
calico.test.test_calcollections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test for collections library.
"""

import logging
from mock import Mock, call, patch

from calico.calcollections import SetDelta, MultiDict
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

    def test_size(self):
        self.assertTrue(self.delta.empty)
        self.assertEqual(self.delta.resulting_size, 3)
        self.delta.add("c")  # No-op, already present.
        self.assertEqual(self.delta.resulting_size, 3)
        self.delta.add("d")  # Put in added set.
        self.assertEqual(self.delta.resulting_size, 4)
        self.delta.add("e")  # Will remain in added set.
        self.assertEqual(self.delta.resulting_size, 5)
        self.delta.remove("c")  # Recorded in remove set.
        self.assertEqual(self.delta.resulting_size, 4)
        self.delta.remove("d")  # Cancels the pending add only.
        self.assertEqual(self.delta.resulting_size, 3)
        self.delta.remove("f")  # No-op.
        self.assertEqual(self.delta.resulting_size, 3)


class TestMultiDict(TestCase):
    def setUp(self):
        super(TestMultiDict, self).setUp()
        self.index = MultiDict()

    def test_add_single(self):
        self.index.add("k", "v")
        self.assertTrue(self.index.contains("k", "v"))
        self.assertEqual(set(self.index.iter_values("k")),
                         set(["v"]))

    def test_add_remove_single(self):
        self.index.add("k", "v")
        self.index.discard("k", "v")
        self.assertFalse(self.index.contains("k", "v"))
        self.assertEqual(self.index._index, {})

    def test_empty(self):
        self.assertFalse(bool(self.index))
        self.assertEqual(self.index.num_items("k"), 0)
        self.assertEqual(list(self.index.iter_values("k")), [])

    def test_add_multiple(self):
        self.index.add("k", "v")
        self.assertTrue(bool(self.index))
        self.assertEqual(self.index.num_items("k"), 1)
        self.index.add("k", "v")
        self.assertEqual(self.index.num_items("k"), 1)
        self.index.add("k", "v2")
        self.assertEqual(self.index.num_items("k"), 2)
        self.index.add("k", "v3")
        self.assertEqual(self.index.num_items("k"), 3)
        self.assertIn("k", self.index)
        self.assertNotIn("k2", self.index)
        self.assertTrue(self.index.contains("k", "v"))
        self.assertTrue(self.index.contains("k", "v2"))
        self.assertTrue(self.index.contains("k", "v3"))
        self.assertEqual(self.index._index, {"k": set(["v", "v2", "v3"])})
        self.assertEqual(set(self.index.iter_values("k")),
                         set(["v", "v2", "v3"]))
        self.index.discard("k", "v")
        self.index.discard("k", "v2")
        self.assertTrue(self.index.contains("k", "v3"))
        self.index.discard("k", "v3")
        self.assertEqual(self.index._index, {})
