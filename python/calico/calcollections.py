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
calico.calcollections
~~~~~~~~~~~~~~~~~~~~~

Collection classes and utils.
"""

import logging

_log = logging.getLogger(__name__)


class SetDelta(object):
    """Represents a change to a base set.

    Tracks the minimum collection of additions and removals required to apply
    the changes to the set.
    """
    def __init__(self, base_set):
        """Constructor.

        :param set base_set: the set to calculate deltas from.
        """
        self.base_set = base_set
        self.added_entries = set()
        self.removed_entries = set()

    def add(self, entry):
        """Record an addition to the set."""
        if entry not in self.base_set:
            # Entry wasn't in the set before so store that it needs to be
            # added.
            self.added_entries.add(entry)
        else:
            # Add overrides any previous remove.
            self.removed_entries.discard(entry)

    def remove(self, entry):
        """Record a removal from the set."""
        if entry in self.base_set:
            # Entry was in the set before so store that it needs to be
            # removed.
            self.removed_entries.add(entry)
        else:
            # Remove overrides any previous add.
            self.added_entries.discard(entry)

    def apply_and_reset(self):
        """Apply the differences to the base set."""
        self.base_set.difference_update(self.removed_entries)
        self.base_set.update(self.added_entries)
        self.removed_entries = set()
        self.added_entries = set()

    @property
    def resulting_size(self):
        return (len(self.base_set) -
                len(self.removed_entries) +
                len(self.added_entries))

    @property
    def empty(self):
        return not (self.added_entries or self.removed_entries)


class MultiDict(object):
    """
    Represents a mapping from key to a set of values.

    Implementation note: as an occupancy optimization, if there is only
    one value for a given key, it is stored as a bare value rather than
    a set of one item.
    """

    def __init__(self, set_cls=set):
        """Constructor.
        :param set_cls: The type of set to use to hold values.  For
               example, setting this to an ordered set type would result in
               the values being sorted.
        """
        self._set_cls = set_cls
        self._index = {}

    def add(self, key, value):
        """Add value to the set of values for the given key.

        Idempotent: does nothing if the mapping is already present.
        """
        # As an occupancy optimization, we only store a set of items if there's
        # more than one.  Otherwise, we store the item itself in the index.

        # Use setdefault to insert the item only if it's not present.
        index_entry = self._index.setdefault(key, value)
        if index_entry != value:
            # Failed to insert the new value as the single entry, examine
            # what we got.
            if isinstance(index_entry, self._set_cls):
                # Already have multiple values for that entry, add the new one
                # to the set.
                index_entry.add(value)
            else:
                # There was an entry but it wasn't the one we tried to add,
                # promote the entry to a set.
                index_entry = self._set_cls([index_entry, value])
                self._index[key] = index_entry

    def discard(self, key, value):
        """Discards a value from the set associated with the given key.

        Idempotent: does nothing if the mapping is already gone.
        """
        if key in self._index:
            index_entry = self._index[key]
            if isinstance(index_entry, self._set_cls):
                # Had multiple values for this key before, remove just this
                # value.
                index_entry.discard(value)
                if len(index_entry) == 1:
                    # No-longer have multiple values go back to storing just a
                    # single value.
                    index_entry = index_entry.pop()
                    self._index[key] = index_entry
            elif index_entry == value:
                # Entry was the only value for this key.  Delete it completely.
                del self._index[key]

    def __contains__(self, item):
        """Implements the 'in' operator, True if the key is present."""
        return item in self._index

    def contains(self, key, value):
        """
        :return: True if the given key/value mapping is present.
        """
        index_entry = self._index.get(key)
        if isinstance(index_entry, self._set_cls):
            return value in index_entry
        else:
            return value == index_entry

    def iter_values(self, key):
        """
        :return: an iterator over the values for the given key.  WARNING:
                 care should be taken not to modify the values associated with
                 that key while iterating.
        """
        if key in self._index:
            index_entry = self._index[key]
            if isinstance(index_entry, self._set_cls):
                return iter(index_entry)
            else:
                return iter([index_entry])
        return iter([])

    def num_items(self, key):
        """
        :return: The number of items associated with the given key.  Returns 0
                 if the key is not in the mapping.
        """
        if key in self._index:
            index_entry = self._index[key]
            if isinstance(index_entry, self._set_cls):
                return len(index_entry)
            else:
                return 1
        return 0

    def __nonzero__(self):
        """Implement bool(<multidict>). True if we have some entries."""
        return bool(self._index)
