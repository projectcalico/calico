# -*- coding: utf-8 -*-
# Copyright 2016 Metaswitch Networks
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
selectors
~~~~~~~~~

Parser for selector expressions, which can match against dicts of labels.

For example, the dict {"a": "b"}, would match a selector such as:

    a in {"b", "c"}

or

    a == "b"

The main entry point is the parse_selector() function, which converts the
string representation of a selector into an object.
"""

from base64 import b64encode
import hashlib
import logging
import operator
from weakref import WeakValueDictionary

from pyparsing import (QuotedString, Word, Forward, Suppress,
                       StringEnd, delimitedList, ParseBaseException,
                       ZeroOrMore, Keyword)

from calico.datamodel_v1 import LABEL_CHARS

_log = logging.getLogger(__name__)


class ExprNode(object):
    __slots__ = []

    def collect_reqd_values(self, pr_set):
        pass

    def collect_str_fragments(self, fragment_list):
        """
        Appends a series of strings to the fragment_list that, when
        concatenated, form a string that parses to this expression.

        This is better than implementing __str__ recursively because it
        avoids an O(n^2) blow-up in the concatentations.

        :param fragment_list: list of fragments to add our contribution to.
        """
        raise NotImplementedError()

    def update_hash(self, h):
        """
        Updates the given hashlib hash object with a value that depends on
        the canonical form of this expression.

        Syntactically-equivalent expressions result in the same update
        to the hash object and hence produce the same hash.  Syntactically
        different expressions give different updates.
        """
        # Generate a sequence of fragments that add up to the canonical
        # version of the expression.
        fragments = []
        self.collect_str_fragments(fragments)
        # Update the hash.  Wrapping with 'selector<...>' prevents the hash
        # from being extended in a way that would clash with something we can
        # generate.  (Probably not an important concern but it doesn't hurt.)
        h.update("selector<")
        for f in fragments:
            h.update(f)
        h.update(">")

    def __repr__(self):
        # Stringifying a tree by recursive concatenation ends up O(n^2) so we
        # defer to a method that collects a series of string fragments and
        # then join them.
        fragments = []
        self.collect_str_fragments(fragments)
        return self.__class__.__name__ + "<%s>" % "".join(fragments)


class NotPresent(object):
    """
    Special value returned when evaluating a missing label.

    It's main purpose is to be unequal to anything that we might compare
    it to.
    """
    pass


class Label(ExprNode):
    __slots__ = ["label_name"]

    def __init__(self, parse_str=None, location=None, tokens=None):
        [self.label_name] = tokens

    def evaluate(self, labels):
        try:
            return labels[self.label_name]
        except KeyError:
            return NotPresent()

    def __hash__(self):
        return hash(self.label_name) * 37 + 0x5bce8abd

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.label_name == other.label_name)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append(self.label_name)


class HasOp(ExprNode):
    __slots__ = ["label_name"]

    def __init__(self, parse_str=None, location=None, tokens=None):
        [self.label_name] = tokens

    def evaluate(self, labels):
        return self.label_name in labels

    def __hash__(self):
        return hash(self.label_name) * 37 + 0x742fe51e

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.label_name == other.label_name)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append("has(%s)" % self.label_name)


class Literal(ExprNode):
    __slots__ = ["value"]

    def __init__(self, parse_str=None, location=None, tokens=None):
        [self.value] = tokens

    def evaluate(self, labels):
        return self.value

    def __hash__(self):
        return hash(self.__class__) * 37 + hash(self.value)

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.value == other.value)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append(repr(self.value))


class SetLiteral(ExprNode):
    __slots__ = ["value"]

    def __init__(self, parse_str=None, location=None, tokens=None):
        self.value = frozenset(tokens)

    def evaluate(self, labels):
        return self.value

    def __hash__(self):
        return hash(self.__class__) * 37 + hash(self.value)

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.value == other.value)

    def collect_str_fragments(self, fragment_list):
        collect_set_string_fragments(fragment_list, self.value)


def collect_set_string_fragments(fragment_list, the_set):
    fragment_list.append("{")
    first = True
    for v in the_set:
        if not first:
            fragment_list.append(",")
        else:
            first = False
        fragment_list.append(repr(v))
    fragment_list.append("}")


def equality_op(parse_str=None, location=None, tokens=None):
    lhs, rhs = tokens
    assert isinstance(lhs, Label) and isinstance(rhs, Literal)
    return LabelToLiteralEquality(lhs.label_name, rhs.value)


def inequality_op(parse_str=None, location=None, tokens=None):
    lhs, rhs = tokens
    return InequalityOp(lhs, rhs)


def in_op(parse_str=None, location=None, tokens=None):
    lhs, rhs = tokens
    assert isinstance(lhs, Label)
    assert isinstance(rhs, SetLiteral)
    return LabelInSetLiteral(lhs.label_name, rhs.value)


def not_in_op(parse_str=None, location=None, tokens=None):
    lhs, rhs = tokens
    return NotInOp(lhs, rhs)


class BinaryOp(ExprNode):
    __slots__ = ["lhs", "rhs"]
    operation = None
    operation_str = None

    def __init__(self, lhs, rhs):
        self.lhs = lhs
        self.rhs = rhs

    def evaluate(self, labels):
        return self.operation(self.lhs.evaluate(labels),
                              self.rhs.evaluate(labels))

    def __hash__(self):
        h = hash(self.__class__)
        h = h * 37 + hash(self.lhs)
        h = h * 37 + hash(self.rhs)
        return h

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.lhs == other.lhs and
                self.rhs == other.rhs)

    def collect_str_fragments(self, fragment_list):
        self.lhs.collect_str_fragments(fragment_list)
        fragment_list.append(" ")
        fragment_list.append(self.operation_str)
        fragment_list.append(" ")
        self.rhs.collect_str_fragments(fragment_list)


class LabelToLiteralEquality(BinaryOp):
    """
    Represents the sub-expression label == "value".

    The LHS stores the name of the label directly, the RHS stores the
    value of the string literal.
    """
    __slots__ = []
    operation = operator.eq
    operation_str = "=="

    def evaluate(self, labels):
        # Since we store the label name and value directly, we need a
        # customized eval function...
        return labels.get(self.lhs) == self.rhs

    def collect_reqd_values(self, pr_set):
        pr_set.add((self.lhs, self.rhs))

    def collect_str_fragments(self, fragment_list):
        fragment_list.append(self.lhs)
        fragment_list.append(" == ")
        fragment_list.append(repr(self.rhs))


class LabelInSetLiteral(BinaryOp):
    """
    Represents the sub-expression label in {"value", "value2" ...}.

    The LHS stores the name of the label directly, the RHS stores the
    value of the set literal.
    """
    __slots__ = []
    operation_str = "in"

    def evaluate(self, labels):
        # Since we store the label name and value directly, we need a
        # customized eval function...
        return labels.get(self.lhs) in self.rhs

    def collect_reqd_values(self, pr_set):
        if len(self.rhs) == 1:
            # We don't have a way to represent alternatives yet so we can only
            # express a requirement if there's only one entry in the set.
            pr_set.update(self.rhs)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append(self.lhs)
        fragment_list.append(" in ")
        collect_set_string_fragments(fragment_list, self.rhs)


class InequalityOp(BinaryOp):
    __slots__ = []
    operation = operator.ne
    operation_str = "!="


class NotInOp(BinaryOp):
    __slots__ = []
    operation_str = "not in"

    @staticmethod
    def operation(a, b):
        return a not in b


class ListOp(ExprNode):
    __slots__ = ["exprs"]
    operator_str = None

    def __init__(self, exprs):
        self.exprs = exprs

    def __hash__(self):
        h = hash(self.__class__)
        for expr in self.exprs:
            h *= 37
            h += hash(expr)
        return h

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.exprs == other.exprs)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append("(")
        first = True
        for child in self.exprs:
            if not first:
                fragment_list.append(" ")
                fragment_list.append(self.operator_str)
                fragment_list.append(" ")
            else:
                first = False
            child.collect_str_fragments(fragment_list)
        fragment_list.append(")")


class AndOp(ListOp):
    __slots__ = []
    operator_str = "&&"

    def evaluate(self, labels):
        for expr in self.exprs:
            value = expr.evaluate(labels)
            if not value:
                return False
        return True

    def collect_reqd_values(self, pr_set):
        for expr in self.exprs:
            expr.collect_reqd_values(pr_set)


def and_op(parse_str=None, location=None, tokens=None):
    if len(tokens) == 1:
        return tokens[0]
    else:
        return AndOp(tokens.asList())


class OrOp(ListOp):
    __slots__ = []
    operator_str = "||"

    def evaluate(self, labels):
        for expr in self.exprs:
            value = expr.evaluate(labels)
            if value:
                return True
        return False

    def collect_reqd_values(self, pr_set):
        first = True
        for expr in self.exprs:
            if first:
                expr.collect_reqd_values(pr_set)
                first = False
            else:
                next_prs = set()
                expr.collect_reqd_values(next_prs)
                pr_set.intersection_update(next_prs)


def or_op(parse_str=None, location=None, tokens=None):
    if len(tokens) == 1:
        return tokens[0]
    else:
        return OrOp(tokens.asList())


class AllOp(ExprNode):
    __slots__ = []

    def evaluate(self, labels):
        return True

    def __hash__(self):
        return 0x844705d8

    def __eq__(self, other):
        return type(other) == type(self)

    def collect_str_fragments(self, fragment_list):
        fragment_list.append("all()")


ALL_OP = AllOp()


class SelectorExpression(object):
    """
    Top-level expression.  Caches hash and the like for its children.
    """

    __slots__ = ["expr_op", "_hash", "_prereq_values", "_unique_id", "_str",
                 "__weakref__"]

    def __init__(self, expr_op):
        super(SelectorExpression, self).__init__()
        self.expr_op = expr_op
        self._hash = hash(expr_op)
        self._unique_id = None
        self._str = None
        self._prereq_values = None

    def evaluate(self, labels):
        return self.expr_op.evaluate(labels)

    @property
    def required_kvs(self):
        """
        A set of label/value tuples that must be set for this selector to
        match.

        For example, selector a = 'b' would return set([("a", "b")])
        """
        if self._prereq_values is None:
            self._prereq_values = set()
            self.expr_op.collect_reqd_values(self._prereq_values)
        return self._prereq_values

    @property
    def unique_id(self):
        """
        Returns a string which is very likely to be unique to this expression.
        Expressions with the same parse tree return the same value.

        The string uses the Base64 alphabet, with - and _ for the "alt chars",
        making it suitable for use as a safe ID for ipsets/iptables chains etc.
        """
        if not self._unique_id:
            h = hashlib.sha224()
            self.expr_op.update_hash(h)
            self._unique_id = b64encode(h.digest(), altchars="_-").rstrip("=")
        return self._unique_id

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return other is self or (type(other) == type(self) and
                                 hash(other) == self._hash and
                                 other.expr_op == self.expr_op)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        if self._str is None:
            fragments = []
            self.expr_op.collect_str_fragments(fragments)
            self._str = "".join(fragments)
        return self._str

    def __repr__(self):
        return self.__class__.__name__ + "<%s>" % self.__str__()


def _define_grammar():
    """
    Creates and returns a copy of the selector grammar.

    Wrapped in a function to avoid polluting the module namespace.
    """
    expr = Forward()

    label_name = Word(LABEL_CHARS)
    label_name.setParseAction(Label)

    string_literal = QuotedString('"') | QuotedString("'")
    string_literal.setParseAction(Literal)

    set_literal = (Suppress("{") +
                   delimitedList(QuotedString('"') | QuotedString("'"), ",") +
                   Suppress("}"))
    set_literal.setParseAction(SetLiteral)

    eq_comparison = label_name + Suppress("==") + string_literal
    eq_comparison.setParseAction(equality_op)

    not_eq_comparison = label_name + Suppress("!=") + string_literal
    not_eq_comparison.setParseAction(inequality_op)

    in_comparison = label_name + Suppress(Keyword("in")) + set_literal
    in_comparison.setParseAction(in_op)

    not_in = Suppress(Keyword("not") + Keyword("in"))
    not_in_comparison = label_name + not_in + set_literal
    not_in_comparison.setParseAction(not_in_op)

    has_check = (Suppress("has(") +
                 Word(LABEL_CHARS) +
                 Suppress(")"))
    has_check.setParseAction(HasOp)

    comparison = (eq_comparison |
                  not_eq_comparison |
                  in_comparison |
                  not_in_comparison |
                  has_check)

    paren_expr = (Suppress("(") + expr + Suppress(")"))

    value = comparison | paren_expr

    and_expr = value + ZeroOrMore(Suppress("&&") + value)
    and_expr.setParseAction(and_op)

    or_expr = and_expr + ZeroOrMore(Suppress("||") + and_expr)
    or_expr.setParseAction(or_op)

    expr << or_expr

    grammar = expr + StringEnd()
    return grammar


class BadSelector(ValueError):
    pass


_grammar = _define_grammar()
_parse_cache = WeakValueDictionary()


def parse_selector(expr_str):
    """
    Parses the given selector string into a SelectorExpression object.

    The returned object is hashable and syntactically-equivalent
    expressions hash and compare equally.

    :param str expr_str: String form of the expression.
    :return: SelectorExpression object.
    :raises BadSelector if the input is not a valid selector expression.
    """
    # Thread safety: multiple threads could access the cache dict concurrently.
    # The worst that can happen is that they both parse the expression and
    # write it back to the cache, which is OK because the two separate
    # SelectorExpressions will behave identically.  Currently, we only
    # parse expressions from the etcd thread so even that shouldn't be an
    # issue.
    try:
        expr = _parse_cache[expr_str]
    except KeyError:
        _log.debug("Expression %s not found in cache, parsing...", expr_str)
        expr = _parse_no_cache(expr_str)
        _parse_cache[expr_str] = expr
    return expr


def _parse_no_cache(expr_str):
    if expr_str.strip() in ("", "all()"):
        # Empty selector matches everything.
        expr_op = ALL_OP
    else:
        try:
            token_list = _grammar.parseString(expr_str)
        except ParseBaseException:
            _log.warning("Bad selector %r", expr_str)
            raise BadSelector(expr_str)
        # Returned value is a list/dict hybrid.  Unpacking it as a list
        # gets the top-level expression object.
        [expr_op] = token_list
    return SelectorExpression(expr_op)
