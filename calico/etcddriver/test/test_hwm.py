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
test_hwm
~~~~~~~~

Tests for high water mark tracking function.
"""

import logging
from unittest import TestCase
from mock import Mock, call, patch
from calico.etcddriver import hwm
from calico.etcddriver.hwm import HighWaterTracker

_log = logging.getLogger(__name__)


class TestHighWaterTracker(TestCase):
    def setUp(self):
        self.hwm = HighWaterTracker()

    def test_mainline(self):
        # Test merging of updates between a snapshot with etcd_index 10 and
        # updates coming in afterwards with indexes 11, 12, ...

        # We use prefix "/a/$" because $ is not allowed in the trie so it
        # implicitly tests encoding/decoding is being properly applied.

        old_hwm = self.hwm.update_hwm("/a/$/c", 9)  # Pre-snapshot
        self.assertEqual(old_hwm, None)
        old_hwm = self.hwm.update_hwm("/b/c/d", 9)  # Pre-snapshot
        self.assertEqual(old_hwm, None)
        old_hwm = self.hwm.update_hwm("/j/c/d", 9)  # Pre-snapshot
        self.assertEqual(old_hwm, None)
        self.assertEqual(len(self.hwm), 3)

        # While merging a snapshot we track deletions.
        self.hwm.start_tracking_deletions()

        # Send in some keys from the snapshot.
        old_hwm = self.hwm.update_hwm("/a/$/c", 10)  # From snapshot
        self.assertEqual(old_hwm, 9)
        old_hwm = self.hwm.update_hwm("/a/$/d", 10)  # From snapshot
        self.assertEqual(old_hwm, None)
        old_hwm = self.hwm.update_hwm("/d/e/f", 10)  # From snapshot
        self.assertEqual(old_hwm, None)
        self.assertEqual(len(self.hwm), 5)

        # This key is first seen in the event stream, so the snapshot version
        # should be ignored.
        old_hwm = self.hwm.update_hwm("/a/h/i", 11)  # From events
        self.assertEqual(old_hwm, None)
        old_hwm = self.hwm.update_hwm("/a/h/i", 10)  # From snapshot
        self.assertEqual(old_hwm, 11)
        old_hwm = self.hwm.update_hwm("/a/h/i", 12)  # From events
        self.assertEqual(old_hwm, 11)  # Still 11, snapshot ignored.
        self.assertEqual(len(self.hwm), 6)

        # Then a whole subtree gets deleted by the events.
        deleted_keys = self.hwm.store_deletion("/a/$", 13)
        self.assertEqual(set(deleted_keys), set(["/a/$/c", "/a/$/d"]))
        self.assertEqual(len(self.hwm), 4)

        # But afterwards, we see a snapshot key within the subtree, it should
        # be ignored.
        old_hwm = self.hwm.update_hwm("/a/$/e", 10)
        self.assertEqual(old_hwm, 13)  # Returns the etcd_index of the delete.
        # Then a new update from the event stream, recreates the directory.
        old_hwm = self.hwm.update_hwm("/a/$/f", 14)
        self.assertEqual(old_hwm, None)
        self.assertEqual(len(self.hwm), 5)
        # And subsequent updates are processed ignoring the delete.
        old_hwm = self.hwm.update_hwm("/a/$/f", 15)
        self.assertEqual(old_hwm, 14)
        # However, snapshot updates from within the deleted subtree are still
        # ignored.
        old_hwm = self.hwm.update_hwm("/a/$/e", 10)
        self.assertEqual(old_hwm, 13)  # Returns the etcd_index of the delete.
        old_hwm = self.hwm.update_hwm("/a/$/f", 10)
        self.assertEqual(old_hwm, 13)  # Returns the etcd_index of the delete.
        old_hwm = self.hwm.update_hwm("/a/$/g", 10)
        self.assertEqual(old_hwm, 13)  # Returns the etcd_index of the delete.
        self.assertEqual(len(self.hwm), 5)
        # But ones outside the subtree ar not.
        old_hwm = self.hwm.update_hwm("/f/g", 10)
        self.assertEqual(old_hwm, None)
        # And subsequent updates are processed ignoring the delete.
        old_hwm = self.hwm.update_hwm("/a/$/f", 16)
        self.assertEqual(old_hwm, 15)

        # End of snapshot: we stop tracking deletions, which should free up the
        # resources.
        self.hwm.stop_tracking_deletions()
        self.assertEqual(self.hwm._deletion_hwms, None)

        # Then, subseqent updates should be handled normally.
        old_hwm = self.hwm.update_hwm("/a/$/f", 17)
        self.assertEqual(old_hwm, 16)  # From previous event
        old_hwm = self.hwm.update_hwm("/g/b/f", 18)
        self.assertEqual(old_hwm, None)  # Seen for the first time.
        old_hwm = self.hwm.update_hwm("/d/e/f", 19)
        self.assertEqual(old_hwm, 10)  # From the snapshot.
        self.assertEqual(len(self.hwm), 7)

        # We should be able to find all the keys that weren't seen during
        # the snapshot.
        old_keys = self.hwm.remove_old_keys(10)
        self.assertEqual(set(old_keys), set(["/b/c/d", "/j/c/d"]))
        self.assertEqual(len(self.hwm), 5)

        # They should now be gone from the index.
        old_hwm = self.hwm.update_hwm("/b/c/d", 20)
        self.assertEqual(old_hwm, None)
        self.assertEqual(len(self.hwm), 6)


class TestKeyEncoding(TestCase):
    def test_encode_key(self):
        self.assert_enc_dec("/calico/v1/foo/bar", "/calico/v1/foo/bar/")

        self.assert_enc_dec("/:_-./foo", "/:_-./foo/")
        self.assert_enc_dec("/:_-.~/foo", "/:_-.%7E/foo/")
        self.assert_enc_dec("/%/foo", "/%25/foo/")
        self.assert_enc_dec(u"/\u01b1/foo", "/%C6%B1/foo/")
        self.assertEqual(hwm.encode_key("/foo/"), "/foo/")

    def assert_enc_dec(self, key, expected_encoding):
        encoded = hwm.encode_key(key)
        self.assertEqual(
            encoded,
            expected_encoding,
            msg="Expected %r to encode as %r but got %r" %
                (key, expected_encoding, encoded))
        decoded = hwm.decode_key(encoded)
        self.assertEqual(
            decoded,
            key,
            msg="Expected %r to decode as %r but got %r" %
                (encoded, key, decoded))
