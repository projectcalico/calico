# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import unittest
import mock

_log = logging.getLogger(__name__)


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        self._exit_patch = mock.patch("calico.felix.actor._exit",
                                      autospec=True)
        self._m_exit = self._exit_patch.start()

    def tearDown(self):
        self._exit_patch.stop()
        self.assertFalse(self._m_exit.called)

    def step_actor(self, actor):
        self.assertFalse(actor._event_queue.empty())
        actor._step()