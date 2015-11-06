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
import json
import logging
import sys
import gc

import gevent

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import mock

_log = logging.getLogger(__name__)


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        self._exit_patch = mock.patch("calico.felix.actor._exit",
                                      autospec=True)
        self._m_exit = self._exit_patch.start()

    def tearDown(self):
        gc.collect()
        self.assertFalse(self._m_exit.called)
        self._exit_patch.stop()

    def step_actor(self, actor):
        # Pretend that the current greenlet is the Actor to bypass
        # actor_message's asserts.
        with mock.patch.object(actor, "greenlet"):
            actor.greenlet = gevent.getcurrent()
            while actor._event_queue:
                actor._step()


class JSONString(object):
    """
    An object that compares equal to a string if it contains equivalent
    JSON to the dict passed to its initializer.
    """

    def __init__(self, json_obj):
        self.json_obj = json_obj

    def __eq__(self, other):
        other_as_obj = None
        try:
            other_as_obj = json.loads(other)
        except (ValueError, KeyError):
            return False
        if other_as_obj == self.json_obj:
            return True
        else:
            _log.error("JSON didn't match %s != %s",
                       self.json_obj, other_as_obj)
            return False

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.json_obj)


class ExpectedException(Exception):
    pass