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
import logging

from calico.calcollections import OneToManyIndex
from calico.felix.selectors import LabelToLiteralEquality, LabelInSetLiteral

_log = logging.getLogger(__name__)


class LinearScanLabelIndex(object):
    """
    A simple baseline implementation of a label index.  Every update
    is handled by a full linear scan.
    """

    def __init__(self):
        # Cache of raw label dicts by item_id.
        self.labels_by_item_id = {}
        # All expressions by ID.
        self.expressions_by_id = {}
        # Map from expression ID to matching item_ids.
        self.matches_by_expr_id = OneToManyIndex()
        self.matches_by_item_id = OneToManyIndex()
        self.total_evaluations = 0

    def on_expression_update(self, expr_id, expr):
        _log.debug("Expression %s updated to %s", expr_id, expr)
        self._scan_all_labels(expr_id, expr)
        self._store_expression(expr_id, expr)

    def on_labels_update(self, item_id, new_labels):
        _log.debug("Labels for %s now %s", item_id, new_labels)
        self._scan_all_expressions(item_id, new_labels)
        self._store_labels(item_id, new_labels)

    def _scan_all_labels(self, expr_id, expr):
        _log.debug("Doing full label scan against expression %s", expr_id)
        for item_id, label_values in self.labels_by_item_id.iteritems():
            self._update_matches(expr_id, expr, item_id, label_values)

    def _scan_all_expressions(self, item_id, new_labels):
        _log.debug("Doing full expression scan against item %s", item_id)
        for expr_id, expr in self.expressions_by_id.iteritems():
            self._update_matches(expr_id, expr, item_id, new_labels)

    def _store_expression(self, expr_id, expr):
        """Updates expressions_by_id with the new value for an expression."""
        if expr is not None:
            self.expressions_by_id[expr_id] = expr
        else:
            self.expressions_by_id.pop(expr_id, None)

    def _store_labels(self, item_id, new_labels):
        """Updates labels_by_item_id with the new labels for an item."""
        if new_labels is not None:
            self.labels_by_item_id[item_id] = new_labels
        else:
            self.labels_by_item_id.pop(item_id, None)

    def _update_matches(self, expr_id, expr, item_id, label_values):
        """
        (Re-)evaluates the given expression against the given labels and
        stores the result.
        """
        _log.debug("Re-evaluating %s against %s (%s)", expr_id, item_id,
                   label_values)
        if expr is not None and label_values is not None:
            now_matches = expr.evaluate(label_values)
            self.total_evaluations += 1
            _log.debug("After evaluation, now matches: %s", now_matches)
        else:
            _log.debug("Expr or labels missing: no match")
            now_matches = False
        # Update the index and generate events.  These methods are idempotent
        # so they'll ignore duplicate updates.
        if now_matches:
            self._store_match(expr_id, item_id)
        else:
            self._discard_match(expr_id, item_id)

    def _store_match(self, expr_id, item_id):
        """
        Stores that an expression matches an item.

        Calls on_match_started() as a side-effect. Idempotent, does
        nothing if the match is already recorded.
        """
        previously_matched = self.matches_by_expr_id.contains(expr_id, item_id)
        if not previously_matched:
            _log.debug("%s now matches: %s", expr_id, item_id)
            self.matches_by_expr_id.add(expr_id, item_id)
            self.matches_by_item_id.add(item_id, expr_id)
            self.on_match_started(expr_id, item_id)

    def _discard_match(self, expr_id, item_id):
        """
        Stores that an expression does not match an item.

        Calls on_match_stopped() as a side-effect.  Idempotent, does
        nothing if the non-match is already recorded.
        """
        previously_matched = self.matches_by_expr_id.contains(expr_id, item_id)
        if previously_matched:
            _log.debug("%s no-longer matches %s", expr_id, item_id)
            self.matches_by_expr_id.discard(expr_id, item_id)
            self.matches_by_item_id.discard(item_id, expr_id)
            self.on_match_stopped(expr_id, item_id)

    def on_match_started(self, expr_id, item_id):
        _log.debug("SelectorExpression %s now matches item %s",
                   expr_id, item_id)

    def on_match_stopped(self, expr_id, item_id):
        _log.debug("SelectorExpression %s no longer matches item %s",
                   expr_id, item_id)


class LabelValueIndex(LinearScanLabelIndex):
    """
    Label index that indexes the values of labels, allowing for efficient
    calculation of selectors of the form 'a == "b" && c == "d"', which
    are the mainline.
    """
    def __init__(self):
        super(LabelValueIndex, self).__init__()
        self.item_ids_by_key_value = OneToManyIndex()
        self.kv_to_literal_expr = OneToManyIndex()
        self.non_kv_expressions_by_id = {}

    def on_labels_update(self, item_id, new_labels):
        _log.debug("Updating labels for %s to %s", item_id, new_labels)
        # Find any old labels associated with this item_id and remove the
        # ones that have changed from the index.
        old_labels = self.labels_by_item_id.get(item_id, {})
        for k_v in old_labels.iteritems():
            k, v = k_v
            if new_labels is None or new_labels.get(k) != v:
                _log.debug("Removing old key/value (%s, %s) from index", k, v)
                self.item_ids_by_key_value.discard(k_v, item_id)
        # Check all the old matches for updates.  Record that we've already
        # re-evaluated these expressions so we can skip them later.
        seen_expr_ids = set()
        old_matches = list(self.matches_by_item_id.iter_values(item_id))
        for expr_id in old_matches:
            seen_expr_ids.add(expr_id)
            self._update_matches(expr_id, self.expressions_by_id[expr_id],
                                 item_id, new_labels)
        if new_labels is not None:
            # Spin through the new labels, storing them in the index and
            # looking for expressions of the form 'k == "v"', which we have
            # indexed.
            for k_v in new_labels.iteritems():
                _log.debug("Adding (%s, %s) to index", *k_v)
                self.item_ids_by_key_value.add(k_v, item_id)
                for expr_id in self.kv_to_literal_expr.iter_values(k_v):
                    if expr_id in seen_expr_ids:
                        continue
                    self._store_match(expr_id, item_id)
                    seen_expr_ids.add(expr_id)
        # Spin through the remaining expressions, which we can't optimize.
        for expr_id, expr in self.non_kv_expressions_by_id.iteritems():
            if expr_id in seen_expr_ids:
                continue
            _log.debug("Checking updated labels against non-indexed expr: %s",
                       expr_id)
            self._update_matches(expr_id, expr, item_id, new_labels)
        # Finally, store the update.
        self._store_labels(item_id, new_labels)

    def on_expression_update(self, expr_id, expr):
        # Remove any old value from the indexes.  We'll then add the expression
        # back in if it's suitable below.
        _log.debug("Expression %s updated to %s", expr_id, expr)
        old_expr = self.expressions_by_id.get(expr_id)

        if old_expr and isinstance(old_expr.expr_op, (LabelToLiteralEquality,
                                                      LabelInSetLiteral)):
            # Either an expression of the form a == "b", or one of the form
            # a in {"b", "c", ...}.  Undo our index for the old entry, we'll
            # then add it back in below.
            label_name = old_expr.expr_op.lhs
            if isinstance(old_expr.expr_op, LabelToLiteralEquality):
                values = [old_expr.expr_op.rhs]
            else:
                values = old_expr.expr_op.rhs
            for value in values:
                _log.debug("Old expression was indexed, removing")
                k_v = label_name, value
                self.kv_to_literal_expr.discard(k_v, expr_id)

        self.non_kv_expressions_by_id.pop(expr_id, None)

        if not expr:
            # Deletion, clean up the matches.
            for item_id in list(self.matches_by_expr_id.iter_values(expr_id)):
                _log.debug("Expression deleted, removing old match: %s",
                           item_id)
                self._update_matches(expr_id, None, item_id,
                                     self.labels_by_item_id[item_id])
        elif isinstance(expr.expr_op, (LabelToLiteralEquality,
                                       LabelInSetLiteral)):
            # Either an expression of the form a == "b", or one of the form
            # a in {"b", "c", ...}.  We can optimise these forms so that
            # they can be evaluated by an exact lookup.
            label_name = expr.expr_op.lhs
            if isinstance(expr.expr_op, LabelToLiteralEquality):
                values = [expr.expr_op.rhs]
            else:
                values = expr.expr_op.rhs

            # Get the old matches as a set.  Then we can discard the items
            # that still match, leaving us with the ones that no-longer
            # match.
            old_matches = set(self.matches_by_expr_id.iter_values(expr_id))
            for value in values:
                _log.debug("New expression is a LabelToLiteralEquality, using "
                           "index")
                k_v = label_name, value
                for item_id in self.item_ids_by_key_value.iter_values(k_v):
                    _log.debug("From index, %s matches %s", expr_id, item_id)
                    old_matches.discard(item_id)
                    self._store_match(expr_id, item_id)
                self.kv_to_literal_expr.add(k_v, expr_id)
            # old_matches now contains only the items that this expression
            # previously matched but no-longer does.  Remove them.
            for item_id in old_matches:
                _log.debug("Removing old match %s, %s", expr_id, item_id)
                self._discard_match(expr_id, item_id)
        else:
            # The expression isn't a super-simple k == "v", let's see if we
            # can still use the index...
            required_kvs = expr.required_kvs if expr else None
            if required_kvs:
                # The expression has some required k == "v" constraints, let's
                # try to find an index that reduces the work we need to do.
                _log.debug("New expression requires these values: %s",
                           required_kvs)
                best_kv = self._find_best_index(required_kvs)
                # Scan over the best index that we found.
                old_matches = set(self.matches_by_expr_id.iter_values(expr_id))
                for item_id in self.item_ids_by_key_value.iter_values(best_kv):
                    old_matches.discard(item_id)
                    self._update_matches(expr_id, expr, item_id,
                                         self.labels_by_item_id[item_id])
                # Clean up any left-over old matches.
                for item_id in old_matches:
                    self._update_matches(expr_id, None, item_id,
                                         self.labels_by_item_id[item_id])
            else:
                # The expression was just too complex to index.  Give up and
                # do a linear scan.
                _log.debug("%s too complex to use indexes, doing linear scan",
                           expr_id)
                self._scan_all_labels(expr_id, expr)
            self.non_kv_expressions_by_id[expr_id] = expr
        # Finally, store the update.
        self._store_expression(expr_id, expr)

    def _find_best_index(self, required_kvs):
        """
        Finds the smallest index for the given set of key/value requirements.

        For example, an expression "env == 'prod' && type == 'foo'" would have
        requirements [("env", "prod"), ("type", "foo")].  Suppose type=="foo"
        only applies to a handful of items but env=="prod" applies to many;
        this method would return ("type", "foo") as the best index.

        :returns the key, value tuple for the best index to use.
        """
        min_kv = None
        min_num = None
        for k_v in required_kvs:
            num = self.item_ids_by_key_value.num_items(k_v)
            if min_num is None or num < min_num:
                min_kv = k_v
                min_num = num
                if num < 10:
                    # Good enough, let's get on with evaluating the
                    # expressions rather than spending more time looking for
                    # a better index.
                    break
        _log.debug("Best index: %s, %s items", min_kv, min_num)
        return min_kv


class LabelInheritanceIndex(object):
    """
    Wraps a LabelIndex, adding the ability for items to inherit labels
    from a list of named parents.
    """
    def __init__(self, label_index):
        self.label_index = label_index
        self.labels_by_item_id = {}
        self.labels_by_parent_id = {}
        self.parent_ids_by_item_id = {}
        self.item_ids_by_parent_id = OneToManyIndex()
        self._dirty_items = set()

    def on_item_update(self, item_id, labels_or_none, parents_or_none):
        _log.debug("Item %s updated: %s, %s", item_id,
                   labels_or_none, parents_or_none)
        self._on_item_labels_update(item_id, labels_or_none)
        self._on_item_parents_update(item_id, parents_or_none)
        self._flush_updates()

    def _on_item_parents_update(self, item_id, parents):
        old_parents = self.parent_ids_by_item_id.get(item_id)
        if old_parents != parents:
            if old_parents:
                for parent_id in old_parents:
                    self.item_ids_by_parent_id.discard(parent_id, item_id)
            if parents is not None:
                for parent_id in parents:
                    self.item_ids_by_parent_id.add(parent_id, item_id)
                self.parent_ids_by_item_id[item_id] = parents
            else:
                del self.parent_ids_by_item_id[item_id]
            self._dirty_items.add(item_id)

    def _on_item_labels_update(self, item_id, labels):
        if self.labels_by_item_id.get(item_id) != labels:
            if labels is not None:
                self.labels_by_item_id[item_id] = labels
            else:
                del self.labels_by_item_id[item_id]
            self._dirty_items.add(item_id)

    def on_parent_labels_update(self, parent_id, labels_or_none):
        _log.debug("Parent labels for %s updated: %s", parent_id,
                   labels_or_none)
        old_parent_labels = self.labels_by_parent_id.get(parent_id)
        if old_parent_labels != labels_or_none:
            if labels_or_none is not None:
                self.labels_by_parent_id[parent_id] = labels_or_none
            else:
                del self.labels_by_parent_id[parent_id]
            self._dirty_items.update(
                self.item_ids_by_parent_id.iter_values(parent_id)
            )
        self._flush_updates()

    def _flush_updates(self):
        _log.debug("Flushing updates...")
        for item_id in self._dirty_items:
            self._flush_item(item_id)
        self._dirty_items.clear()

    def _flush_item(self, item_id):
        try:
            item_labels = self.labels_by_item_id[item_id]
        except KeyError:
            # Labels deleted, pass that through.
            _log.debug("Flushing deletion of %s", item_id)
            self.label_index.on_labels_update(item_id, None)
        else:
            # May need to combine labels with parents.
            _log.debug("Combining labels for %s", item_id)
            combined_labels = {}
            parent_ids = self.parent_ids_by_item_id.get(item_id, [])
            _log.debug("Item %s has parents %s", item_id, parent_ids)
            for parent_id in parent_ids:
                parent_labels = self.labels_by_parent_id.get(parent_id)
                _log.debug("Parent %s has labels %s", parent_id, parent_labels)
                if parent_labels:
                    combined_labels.update(parent_labels)
            if combined_labels:
                # Some contribution from parent, need to combine.
                _log.debug("Combined labels: %s", combined_labels)
                combined_labels.update(item_labels)
            else:
                # Parent makes no contribution, just use the per-item dict.
                _log.debug("No parent labels, using item's dict %s",
                           combined_labels)
                combined_labels = item_labels
            self.label_index.on_labels_update(item_id, combined_labels)