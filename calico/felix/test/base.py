# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import sys
import gevent
import gc

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
            while not actor._event_queue.empty():
                actor._step()
