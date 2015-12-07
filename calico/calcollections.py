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
