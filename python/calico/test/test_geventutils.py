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
test_geventutils
~~~~~~~~~~~~~~~~

Test code for gevent utility functions.
"""

import logging
import gevent
from calico import geventutils

from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


class TestGreenletUtils(BaseTestCase):

    def test_greenlet_id(self):
        def greenlet_run():
            tid = geventutils.greenlet_id()
            return tid

        tid = geventutils.greenlet_id()
        child = gevent.spawn(greenlet_run)
        child_tid = child.get()
        new_tid = geventutils.greenlet_id()

        self.assertTrue(child_tid > tid)
        self.assertEqual(tid, new_tid)
