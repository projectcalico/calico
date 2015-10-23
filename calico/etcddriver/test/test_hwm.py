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
test_hwm
~~~~~~~~

Tests for high water mark tracking function.
"""

import logging
from unittest import TestCase
from mock import Mock, call, patch
from calico.etcddriver import hwm

_log = logging.getLogger(__name__)


class TestHighWaterTracker(TestCase):
    pass


class TestKeyEncoding(TestCase):
    def test_encode_key(self):
        self.assert_enc_dec("/calico/v1/foo/bar", "/calico/v1/foo/bar/")

        self.assert_enc_dec("/:_-./foo", "/:_-./foo/")
        self.assert_enc_dec("/:_-.~/foo", "/:_-.%7E/foo/")
        self.assert_enc_dec("/%/foo", "/%25/foo/")
        self.assert_enc_dec(u"/\u01b1/foo", "/%C6%B1/foo/")

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

