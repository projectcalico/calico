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
test_selectors
~~~~~~~~~~~~~~

Tests for the label selectors.
"""

import logging
import re

from hypothesis import given
from hypothesis.strategies import text, lists, sampled_from
from nose.tools import *
from calico.felix.selectors import (parse_selector, SelectorExpression,
                                    BadSelector, ExprNode)
from calico.test.utils import fail_if_time_exceeds

_log = logging.getLogger(__name__)


# These tests use nose's test generator feature to generate a set of tests that
# can each pass or fail independently.

def test_matches():

    # Individual operators...
    yield check_match, "a == 'a'", {"a": "a"}
    yield check_match, 'a == "a"', {"a": "a"}
    yield check_match, 'a != "b"', {"a": "a"}
    yield check_match, 'a != "a"', {}
    yield check_match, 'a in {"a"}', {"a": "a"}
    yield check_match, '!a in {"a"}', {"a": "b"}
    yield check_match, 'a in {"a", "b"}', {"a": "a"}
    yield check_match, 'a in {"a", "b"}', {"a": "b"}
    yield check_match, 'a not in {"d", "e"}', {"a": "a"}
    yield check_match, 'has(a)', {"a": "b"}
    yield check_match, '!has(a)', {"b": "b"}
    yield check_match, '', {}
    yield check_match, ' ', {}
    yield check_match, '', {"a": "b"}
    yield check_match, 'all()', {}
    yield check_match, ' all()', {}
    yield check_match, ' all()', {"a": "b"}

    yield check_no_match, "a == 'a'", {"a": "b"}
    yield check_no_match, "a == 'a'", {}
    yield check_no_match, 'a != "a"', {"a": "a"}
    yield check_no_match, 'a in {"a"}', {"a": "b"}
    yield check_no_match, 'a not in {"a"}', {"a": "a"}
    yield check_no_match, 'a in {"a", "b"}', {"a": "c"}
    yield check_no_match, 'has(b)', {"a": "b"}
    yield check_no_match, '!!has(b)', {"a": "b"}
    yield check_no_match, '! has(a)', {"a": "b"}
    yield check_no_match, '!has(a)', {"a": "b"}
    yield check_no_match, '!!! has(a)', {"a": "b"}
    yield check_no_match, '!!!has(a)', {"a": "b"}
    yield check_no_match, '!! ! has(a)', {"a": "b"}
    yield check_no_match, '! !!has(a)', {"a": "b"}

    # Boolean expressions...
    yield check_match, "a == 'a1' && b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "a == 'a1' && b != 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "a != 'a1' && b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "a != 'a1' && b != 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "a != 'a1' && !b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "!a == 'a1' && b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_match, 'has(a) && !has(b)', {"a": "a"}
    yield check_match, '!has(b) && has(a)', {"a": "a"}
    yield check_match, '!(!has(a) || has(b))', {"a": "a"}
    yield check_match, '!(has(b) || !has(a))', {"a": "a"}

    yield check_match, "a == 'a1' || b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_match, "a == 'a1' || b != 'b1'", {"a": "a1", "b": "b1"}
    yield check_match, "a != 'a1' || b == 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "a != 'a1' || b != 'b1'", {"a": "a1", "b": "b1"}
    yield check_no_match, "! a == 'a1' || ! b == 'b1'", {"a": "a1", "b": "b1"}

    # Bad selectors
    yield check_bad_selector, "b == b"  # label == label
    yield check_bad_selector, "'b1' == b"  # literal on lhs
    yield check_bad_selector, "b"  # bare label
    yield check_bad_selector, "a b"  # Garbage
    yield check_bad_selector, "!"  # Garbage


def test_prereq_values():
    # Individual operators...
    yield check_prereqs, "a == 'a1'", [("a", "a1")]
    yield check_prereqs, "a != 'a1'", []
    yield check_prereqs, 'a in {"a1", "b1"}', []
    yield check_prereqs, 'a in {"a1"}', ["a1"]
    yield check_prereqs, 'a not in {"a1", "b1"}', []
    yield check_prereqs, 'has(a)', []

    # Boolean expressions...
    yield check_prereqs, "a == 'a1' && b == 'b1'", [("a", "a1"), ("b", "b1")]
    yield check_prereqs, "a == 'a1' && has(b)", [("a", "a1")]
    yield check_prereqs, "a == 'a1' || b == 'b1'", []
    yield check_prereqs, "a == 'a1' || a == 'a1'", [("a", "a1")]


def test_unique_id():
    seen_ids = {}

    def check_ids_equal(selector_1, selector_2):
        e = parse_selector(selector_1)
        uid_1 = e.unique_id
        e = parse_selector(selector_2)
        uid_2 = e.unique_id
        assert_equal(uid_1, uid_2)
        assert_true(re.match(r'^[a-zA-Z0-9_-]{38}$', uid_1))
        assert_not_in(uid_1, seen_ids,
                      msg="Selector %r unexpectedly had same unique ID as %r" %
                          (selector_1, seen_ids.get(uid_1)))
        seen_ids[uid_1] = selector_1

    check_ids_equal("a == 'b'", "a ==  'b'")
    check_ids_equal("b == 'b'", "b ==  'b'")
    check_ids_equal("a != 'b'", ' a  != "b"')
    check_ids_equal("a in {'b'}", ' a  in {"b"}')
    check_ids_equal("a in {'c'}", ' a  in {"c"}')
    check_ids_equal("a != 'b' && c == 'd'", "a != 'b'&&c == 'd'")
    check_ids_equal("a != 'b' || c == 'd'", "a != 'b'||c == 'd'")
    check_ids_equal("a != 'b' || c == ''", "(a != 'b'||c == '')")
    check_ids_equal("!a == 'b' || c == ''", "(!a == 'b'||c == '')")
    check_ids_equal("!all()", "!( all())")
    for x in xrange(100):
        sel = "a == '%s' && c != 'd' || e in {'f'} || d not in {'g'}" % x
        sel2 = re.sub(r' ', "  ", sel)
        check_ids_equal(sel, sel2)


def test_repr():
    sel = "a== 'a'  && c != 'd' ||  e in {'f'}  || d not in {'g' }"
    e = parse_selector(sel)
    assert_equal(repr(e),
                 "SelectorExpression<((a == 'a' && c != 'd') || "
                 "e in {'f'} || d not in {'g'})>")
    assert_equal(repr(e.expr_op),
                 "OrNode<((a == 'a' && c != 'd') || "
                 "e in {'f'} || d not in {'g'})>")


def test_missing_collect():
    # For coverage...
    e = ExprNode()
    assert_raises(NotImplementedError, e.collect_str_fragments, [])


@given(text(max_size=20))
@fail_if_time_exceeds(1)
def test_parse_gives_correct_exc_or_value(s):
    try:
        expr = parse_selector(s)
    except BadSelector:
        pass
    except KeyboardInterrupt:
        print "Interrupted while processing %r" % s
        raise
    else:
        assert isinstance(expr, SelectorExpression)
        expr.evaluate({})


@given(lists(sampled_from(["a", '"a"', "b", "||", "|", "&&", "(", ")", "has(",
                           "has", "==", "!=", "in", "not", "{", "}",
                           '{"a","b"}', ",", " ", "&", "!"])))
@fail_if_time_exceeds(1)
def test_plausible_garbage(l):
    try:
        sel = "".join(l)
        expr = parse_selector(sel)
    except BadSelector:
        pass
    else:
        assert isinstance(expr, SelectorExpression)
        expr.evaluate({})


def check_match(selector, labels):
    expr = parse_selector(selector)
    assert_true(expr.evaluate(labels),
                "%r did not match %s" % (selector, labels))
    if selector.strip():
        # Check that wrapping the selector in a negation reverses its effect.
        negated_expr = parse_selector("!(%s)" % selector)
        assert_false(negated_expr.evaluate(labels),
                     "Negated version of %r unexpectedly matched %s" %
                     (selector, labels))
    assert_general_expression_properties(expr)


def assert_general_expression_properties(expr):
    assert_equal(expr, expr, "%r wasn't equal to self" % expr)
    expr2 = parse_selector(str(expr))
    expr2a = parse_selector(str(expr))
    assert_true(expr2 is expr2a)
    expr3 = parse_selector(str(expr) + " ")
    assert_true(expr3 is not expr, "Expected to defeat cache")
    assert_equal(expr3, expr, "Selector parsed from equivalent input should "
                              "be equal")
    assert_false(expr3 != expr, "!= operator should be inverse of ==")
    assert_equal(hash(expr3), hash(expr),
                 "Hashes of equal objects should be equal")
    assert_equal(expr.unique_id, expr2.unique_id, "Unique ids should be equal")
    assert_equal(expr.unique_id, expr3.unique_id, "Unique ids should be equal")


def check_no_match(selector, labels):
    expr = parse_selector(selector)
    assert_false(expr.evaluate(labels),
                 "%r unexpectedly matched %s" % (selector, labels))
    if selector.strip():
        # Check that wrapping the selector in a negation reverses its effect.
        negated_expr = parse_selector("!(%s)" % selector)
        assert_true(negated_expr.evaluate(labels),
                    "Negated version of %r unexpectedly matched %s" %
                    (selector, labels))
    assert_general_expression_properties(expr)


def check_bad_selector(selector):
    assert_raises(BadSelector, parse_selector, selector)


def check_prereqs(selector, expected):
    expr = parse_selector(selector)
    assert_equal(expr.required_kvs, set(expected))
    assert_general_expression_properties(expr)
