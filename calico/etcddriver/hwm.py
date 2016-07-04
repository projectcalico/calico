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
calico.etcddriver.hwm
~~~~~~~~~~~~~~~~~~~~~

The HighWaterTracker is used to resolve the high water mark for each etcd
key when processing a snapshot and event stream in parallel.
"""

import logging
import re
import string

from datrie import Trie
import datrie
import urllib

_log = logging.getLogger(__name__)

# The trie implementation that we use requires us to specify the character set
# in advance...
# Symbols that are allowed in our etcd keys.
TRIE_SYMBOLS = "/_-:."
# Chars we allow in the trie.  In addition to alphanumerics and our
# white-listed symbols, we also use % for %-encoding of unexpected symbols.
TRIE_CHARS = string.ascii_letters + string.digits + TRIE_SYMBOLS + "%"
# Regex that matches chars that are allowed in the trie.
TRIE_CHARS_MATCH = re.compile(r'^[%s]+$' % re.escape(TRIE_CHARS))


class HighWaterTracker(object):
    """
    Tracks the highest etcd index for which we've seen a particular
    etcd key.

    This class is expected to be used as follows:

    Starting with a resync, while also merging events from our watch on etcd:

    * Call start_tracking_deletions() to enable resolution between events
      and the snapshot.
    * Repeatedly call update_hwm() and store_deletion(), feeding in the
      data from the snapshot and event stream.
    * At the end of the snapshot processing, call stop_tracking_deletions()
      to discard the tracking metadata (which would otherwise grow
      indefinitely).
    * Call remove_old_keys() to find and delete any keys that have not been
      seen since before the snapshot was started, and hence must have been
      deleted before the snapshot was taken.

    While in sync:

    * feed in events with update_hwm() and store_deletion().

    At any point, if a new resync is required restart from
    "Call start_tracking_deletions()..."

    """
    def __init__(self):
        # We use a trie to track the highest etcd index at which we've seen
        # each key.  The trie implementation forces a fixed character set;
        # we explicitly allow the characters we expect and encode any others
        # that we're not expecting.
        self._hwms = Trie(TRIE_CHARS)

        # Set to a Trie while we're tracking deletions.  None otherwise.
        self._deletion_hwms = None
        # Optimization: tracks the highest etcd index at which we've seen a
        # deletion.  This allows us to skip an expensive lookup in the
        # _deletion_hwms trie for events that come after the deletion.
        self._latest_deletion = None

    def start_tracking_deletions(self):
        """
        Starts tracking which subtrees have been deleted so that update_hwm
        can skip updates to keys that have subsequently been deleted.

        Should be paired with a call to stop_tracking_deletions() to release
        the associated tracking data structures.
        """
        _log.info("Started tracking deletions")
        self._deletion_hwms = Trie(TRIE_CHARS)
        self._latest_deletion = None

    def stop_tracking_deletions(self):
        """
        Stops deletion tracking and frees up the associated resources.

        Calling this asserts that subsequent calls to update_hwm() will only
        use HWMs after any stored deletes.
        """
        _log.info("Stopped tracking deletions")
        self._deletion_hwms = None
        self._latest_deletion = None

    def update_hwm(self, key, new_mod_idx):
        """
        Updates the HWM for a key if the new value is greater than the old.
        If deletion tracking is enabled, resolves deletions so that updates
        to subtrees that have been deleted are skipped iff the deletion is
        after the update in HWM order.

        :return int|NoneType: the old HWM of the key (or the HWM at which it
                was deleted) or None if it did not previously exist.
        """
        _log.debug("Updating HWM for %s to %s", key, new_mod_idx)
        key = encode_key(key)
        if (self._deletion_hwms is not None and
                # Optimization: avoid expensive lookup if this update comes
                # after all deletions.
                new_mod_idx < self._latest_deletion):
            # We're tracking deletions, check that this key hasn't been
            # deleted.
            del_hwm = self._deletion_hwms.longest_prefix_value(key, None)
            if new_mod_idx < del_hwm:
                _log.debug("Key %s previously deleted, skipping", key)
                return del_hwm
        try:
            old_hwm = self._hwms[key]  # Trie doesn't have get().
        except KeyError:
            old_hwm = None
        if old_hwm < new_mod_idx:  # Works for None too.
            _log.debug("Key %s HWM updated to %s, previous %s",
                       key, new_mod_idx, old_hwm)
            self._hwms[key] = new_mod_idx
        return old_hwm

    def store_deletion(self, key, deletion_mod_idx):
        """
        Store that a given key (or directory) was deleted at a given HWM.
        :return: List of known keys that were deleted.  This will be the
                 leaves only when a subtree is being deleted.
        """
        _log.debug("Key %s deleted", key)
        key = encode_key(key)
        self._latest_deletion = max(deletion_mod_idx, self._latest_deletion)
        if self._deletion_hwms is not None:
            _log.debug("Tracking deletion in deletions trie")
            self._deletion_hwms[key] = deletion_mod_idx
        deleted_keys = []
        for child_key, child_mod in self._hwms.items(key):
            del self._hwms[child_key]
            deleted_keys.append(decode_key(child_key))
        _log.debug("Found %s keys deleted under %s", len(deleted_keys), key)
        return deleted_keys

    def remove_old_keys(self, hwm_limit):
        """
        Deletes and returns all keys that have HWMs less than hwm_limit.
        :return: list of keys that were deleted.
        """
        assert not self._deletion_hwms, \
            "Delete tracking incompatible with remove_old_keys()"
        _log.info("Removing keys that are older than %s", hwm_limit)
        old_keys = []
        state = datrie.State(self._hwms)
        state.walk(u"")
        it = datrie.Iterator(state)
        while it.next():
            value = it.data()
            if value < hwm_limit:
                old_keys.append(it.key())
        for old_key in old_keys:
            del self._hwms[old_key]
        _log.info("Deleted %s old keys", len(old_keys))
        return map(decode_key, old_keys)

    def __len__(self):
        return len(self._hwms)


def encode_key(key):
    """
    Encode an etcd key for use in the trie.

    This does three things:
    * Encodes any characters that are not supported by the trie using
      %-encoding.
    * Adds a trailing slash if not present.  This prevents /foobar/baz from
      being seen as a subtree of /foo/.
    * Converts the result to a unicode string, which is what is required
      by the trie.

    Since our datamodel specifies the characters that are allowed, the first
    operation should be a no-op on most keys but it's better to be tolerant
    here than to blow up.
    """
    if key[-1] != "/":
        suffixed_key = key + "/"
    else:
        suffixed_key = key
    encoded_key = unicode(urllib.quote(suffixed_key.encode("utf8"),
                                       safe=TRIE_SYMBOLS))
    assert TRIE_CHARS_MATCH.match(encoded_key), (
        "Key %r encoded to %r contained invalid chars" % (key, encoded_key)
    )
    return encoded_key


def decode_key(key):
    """
    Reverses the encoding done by encode_key.
    """
    key = urllib.unquote(key.encode("utf8")).decode("utf8")
    return key[:-1]
