# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
test_labels
~~~~~~~~~~~

Tests for the label-indexing function.
"""

import logging

import unittest2
from mock import Mock, call, patch

from calico.felix.labels import LinearScanLabelIndex, LabelValueIndex, \
    LabelInheritanceIndex
from calico.felix.selectors import parse_selector
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


class _LabelTestBase(unittest2.TestCase):
    cls_to_test = None

    def setUp(self):
        super(_LabelTestBase, self).setUp()
        self.index = self.cls_to_test()
        self.updates = []
        self.index.on_match_started = self.on_match_started
        self.index.on_match_stopped = self.on_match_stopped

    def tearDown(self):
        self.assert_no_updates()  # All updates should be accounted for
        super(_LabelTestBase, self).tearDown()

    def on_match_started(self, expr, item):
        self.cls_to_test.on_match_started(self.index, expr, item)
        self.updates.append(("add", expr, item))

    def on_match_stopped(self, expr, item):
        self.cls_to_test.on_match_stopped(self.index, expr, item)
        self.updates.append(("remove", expr, item))

    def test_mainline(self):
        # Add some labels.
        self.index.on_labels_update("l1", {"a": "a1", "b": "b1", "c": "c1"})
        self.assert_no_updates()
        # Add a non-matching expression
        self.index.on_expression_update("e1", parse_selector('d=="d1"'))
        self.assert_no_updates()
        # Add a matching expression
        self.index.on_expression_update("e2", parse_selector('a=="a1"'))
        self.assert_add("e2", "l1")
        self.assert_no_updates()
        # Update matching expression, still matches
        self.index.on_expression_update("e2", parse_selector('b=="b1"'))
        self.assert_no_updates()
        # Update matching expression, no-longer matches
        self.index.on_expression_update("e2", parse_selector('b=="b2"'))
        self.assert_remove("e2", "l1")
        self.assert_no_updates()
        # Update labels to match.
        self.index.on_labels_update("l1", {"b": "b2", "d": "d1"})
        self.assert_add("e1", "l1")
        self.assert_add("e2", "l1")
        self.assert_no_updates()
        self.index.on_labels_update("l1", None)
        self.assert_remove("e1", "l1")
        self.assert_remove("e2", "l1")
        self.index.on_expression_update("e1", None)
        self.index.on_expression_update("e2", None)
        self.assert_indexes_empty()

    def test_multiple_matches(self):
        # Insert some labels.
        self.index.on_labels_update("l1", {"a": "a", "b": "b1"})
        self.index.on_labels_update("l2", {"a": "a", "b": "b2"})
        self.index.on_labels_update("l3", {"a": "a", "b": "b3"})
        self.index.on_labels_update("l4", {"c": "c1"})
        # And some expressions.
        self.index.on_expression_update("e1", parse_selector('a=="a"'))
        # e2 starts off matching l4, which only has index entries for c==c1.
        # This ensures that we hit the cleanup code when we change e2 because
        # the the indexes that apply to the new value of e2 don't apply to
        # l4.
        self.index.on_expression_update("e2", parse_selector('c=="c1"'))
        self.assert_add("e2", "l4")
        self.index.on_expression_update("e2",
                                        parse_selector('a=="a" && b=="b1"'))
        self.assert_remove("e2", "l4")
        self.assert_add("e1", "l1")
        self.assert_add("e1", "l2")
        self.assert_add("e1", "l3")
        self.assert_add("e2", "l1")
        self.assert_no_updates()
        
        self.index.on_expression_update("e1", parse_selector('a=="z"'))
        self.assert_remove("e1", "l1")
        self.assert_remove("e1", "l2")
        self.assert_remove("e1", "l3")
        self.assert_no_updates()
        self.index.on_expression_update("e1", None)
        self.assert_no_updates()
        self.index.on_expression_update("e2", None)
        self.assert_remove("e2", "l1")
        self.index.on_expression_update("e4", None)
        self.assert_no_updates()

    def test_non_equality_stale_match(self):
        self.index.on_labels_update("l1", {"a": "a", "b": "b1"})
        self.index.on_labels_update("l2", {"a": "a", "b": "b2"})
        self.index.on_labels_update("l3", {"a": "a", "b": "b3"})
        self.index.on_expression_update("e1", parse_selector('b == "b1" && '
                                                             'a == "a"'))
        self.assert_add("e1", "l1")
        self.assert_no_updates()
        self.index.on_expression_update("e1", parse_selector('b == "b2" && '
                                                             'a == "a"'))
        self.assert_remove("e1", "l1")
        self.assert_add("e1", "l2")
        self.assert_no_updates()

    def test_set_indexing(self):
        self.index.on_labels_update("l1", {"a": "a", "b": "b1"})
        self.index.on_labels_update("l2", {"a": "a", "b": "b2"})
        self.index.on_labels_update("l3", {"a": "a2", "b": "b3"})

        # Add an expression with existing labels.
        self.index.on_expression_update("e1",
                                        parse_selector("a in {'a', 'z'}"))
        self.assert_add("e1", "l1")
        self.assert_add("e1", "l2")

        # And one that uses a real set.
        self.index.on_expression_update("e2",
                                        parse_selector("b in {'b1', 'b2'}"))
        self.assert_add("e2", "l1")
        self.assert_add("e2", "l2")
        self.assert_no_updates()

        # Then update them.
        self.index.on_expression_update("e2",
                                        parse_selector("b in {'b2', 'b3'}"))
        self.assert_add("e2", "l3")
        self.assert_remove("e2", "l1")
        self.assert_no_updates()

        self.index.on_expression_update("e1",
                                        parse_selector("a in {'a2'}"))
        self.assert_add("e1", "l3")
        self.assert_remove("e1", "l1")
        self.assert_remove("e1", "l2")
        self.assert_no_updates()

        # Then update the labels:
        self.index.on_labels_update("l1", {"a": "a2", "b": "b1"})
        self.index.on_labels_update("l2", {"b": "b2"})
        self.assert_add("e1", "l1")

    def test_negative_matches(self):
        self.index.on_labels_update("l0", {})
        self.index.on_labels_update("l1", {"a": "a", "b": "b1"})
        self.index.on_labels_update("l2", {"a": "a2", "b": "b2"})
        self.index.on_labels_update("l3", {"a": "a3", "c": "c3"})
        self.index.on_expression_update("not_a", parse_selector('a!="a"'))
        self.index.on_expression_update("not_d", parse_selector('d!="d"'))
        self.assert_add("not_d", "l0")
        self.assert_add("not_d", "l1")
        self.assert_add("not_d", "l2")
        self.assert_add("not_d", "l3")
        self.assert_add("not_a", "l0")
        self.assert_add("not_a", "l2")
        self.assert_add("not_a", "l3")
        self.assert_no_updates()
        self.index.on_labels_update("l2", {"a": "a", "b": "b2"})
        self.assert_remove("not_a", "l2")
        self.assert_no_updates()
        self.index.on_labels_update("l1", {"a": "a", "d": "d1"})
        self.index.on_labels_update("l2", {"a": "a", "d": "d"})
        self.assert_remove("not_d", "l2")
        self.assert_no_updates()
        self.index.on_expression_update("not_a", None)
        self.index.on_expression_update("not_d", None)
        self.assert_remove("not_a", "l0")
        self.assert_remove("not_a", "l3")
        self.assert_remove("not_d", "l1")
        self.assert_remove("not_d", "l0")
        self.assert_remove("not_d", "l3")
        self.index.on_labels_update("l0", None)
        self.index.on_labels_update("l1", None)
        self.index.on_labels_update("l2", None)
        self.index.on_labels_update("l3", None)
        self.assert_indexes_empty()

    def test_inheritance_index_mainline(self):
        ii = LabelInheritanceIndex(self.index)

        ii.on_item_update("item_1", {}, [])
        ii.on_item_update("item_2", {"a": "a1"}, [])
        ii.on_item_update("item_3", {}, ["parent_1"])
        ii.on_item_update("item_4", {"a": "a1"}, ["parent_2"])

        self.index.on_expression_update("e1", parse_selector("a == 'a1'"))
        self.index.on_expression_update("e2", parse_selector("a != 'a1'"))
        self.index.on_expression_update("e3", parse_selector("a == 'p1'"))

        self.assert_add("e1", "item_2")
        self.assert_add("e1", "item_4")
        self.assert_add("e2", "item_1")
        self.assert_add("e2", "item_3")
        self.assert_no_updates()

        # Now make a parent change, should cause a match.
        ii.on_parent_labels_update("parent_1", {"a": "p1"})
        self.assert_add("e3", "item_3")
        # Then, remove the parent label, should remove the match.
        ii.on_parent_labels_update("parent_1", {})
        self.assert_remove("e3", "item_3")

        # Now make a parent change, should cause a match.
        ii.on_parent_labels_update("parent_1", {"a": "p1"})
        self.assert_add("e3", "item_3")
        # Then, remove the parent labels entirely, should remove the match.
        ii.on_parent_labels_update("parent_1", None)
        self.assert_remove("e3", "item_3")

        # Now make a parent change for parent_2; the per-item labels should
        # override.
        ii.on_parent_labels_update("parent_2", {"a": "p1"})
        ii.on_parent_labels_update("parent_2", None)
        self.assert_no_updates()

        # Now make a parent change, should cause a match.
        ii.on_parent_labels_update("parent_1", {"a": "p1"})
        self.assert_add("e3", "item_3")
        # But then remove the item.
        ii.on_item_update("item_3", None, None)
        self.assert_remove("e3", "item_3")
        self.assert_remove("e2", "item_3")

    def assert_indexes_empty(self):
        raise NotImplementedError()

    def assert_no_updates(self):
        self.assertEqual(self.updates, [])

    def assert_add(self, expr, item):
        try:
            self.updates.remove(("add", expr, item))
        except ValueError:
            self.fail("add %s, %s not found in %s" %
                      (expr, item, self.updates))

    def assert_remove(self, expr, item):
        try:
            self.updates.remove(("remove", expr, item))
        except ValueError:
            self.fail("add %s, %s not found in %s" %
                      (expr, item, self.updates))


class TestLinearScanLabelIndex(_LabelTestBase):
    cls_to_test = LinearScanLabelIndex

    def assert_indexes_empty(self):
        self.assertFalse(self.index.labels_by_item_id)
        self.assertFalse(self.index.expressions_by_id)
        self.assertFalse(self.index.matches_by_expr_id)
        self.assertFalse(self.index.matches_by_item_id)


class TestLabelValueIndex(TestLinearScanLabelIndex):
    cls_to_test = LabelValueIndex

    def assert_indexes_empty(self):
        super(TestLabelValueIndex, self).assert_indexes_empty()
        self.assertFalse(self.index.item_ids_by_key_value)
        self.assertFalse(self.index.literal_exprs_by_kv)
        self.assertFalse(self.index.non_kv_expressions_by_id)
