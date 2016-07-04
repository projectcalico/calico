# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
felix.test.test_actor
~~~~~~~~~~~~~~~~~~~~~

Tests of the Actor framework.
"""

import gc
import itertools
import logging
import sys

import mock
from gevent.event import AsyncResult

from calico.felix import actor
from calico.felix.actor import actor_message, ResultOrExc, SplitBatchAndRetry
from calico.felix.test.base import BaseTestCase, ExpectedException

# Logger
log = logging.getLogger(__name__)


# noinspection PyUnresolvedReferences
class TestActor(BaseTestCase):
    def setUp(self):
        super(TestActor, self).setUp()
        self._actor = ActorForTesting()
        mock.patch.object(self._actor, "_start_msg_batch",
                          wraps=self._actor._start_msg_batch).start()
        mock.patch.object(self._actor, "_finish_msg_batch",
                          wraps=self._actor._finish_msg_batch).start()

    def run_actor_loop(self):
        self._actor._step()

    @mock.patch("gevent.Greenlet.start", autospec=True)
    def test_start(self, m_start):
        """
        Tests starting the actor starts its greenlet.
        """
        actor = self._actor.start()
        m_start.assert_called_once_with(self._actor.greenlet)
        self.assertEqual(actor, self._actor)

    def test_single_msg(self):
        """
        Tests a batch with one message in it is correctly processed
        on the queue with start/finish batch wrapped around it.
        """
        self._actor.do_a(async=True)
        # Nothing should happen since it should be queued.
        self.assertEqual(self._actor.actions, [])
        self.run_actor_loop()
        # Then we should get a start, batch of only a and a finish.
        self.assertEqual(self._actor.actions, ["sb", "a", "fb"])

    def test_batch(self):
        """
        Tests a batch with multiple messages in it is correctly processed
        on the queue with start/finish batch wrapped around it.
        """
        self._actor.do_a(async=True)
        self._actor.do_a(async=True)
        self._actor.do_b(async=True)
        self._actor.do_a(async=True)
        # Nothing should happen since it should be queued.
        self.assertEqual(self._actor.actions, [])
        self.run_actor_loop()
        # Then we should get a start, batch of only a and a finish.
        self.assertEqual(self._actor.actions, ["sb", "a", "a", "b", "a", "fb"])

    def test_exception(self):
        """
        Tests an exception raised by an event method is returned to the
        correct AsyncResult.
        """
        f_a = self._actor.do_a(async=True)
        f_exc = self._actor.do_exc(async=True)
        f_b = self._actor.do_b(async=True)
        self.run_actor_loop()
        self.assertTrue(f_a.ready())
        self.assertTrue(f_exc.ready())
        self.assertTrue(f_b.ready())
        self.assertEqual("a", f_a.get())
        self.assertEqual("b", f_b.get())
        self.assertRaises(ExpectedException, f_exc.get)
        self.assertRaises(ExpectedException, actor.wait_and_check,
                          [f_a, f_b, f_exc])
        self.assertEqual(self._actor.actions, ["sb", "a", "exc", "b", "fb"])
        self._actor._finish_msg_batch.assert_called_once_with(mock.ANY, [
            ResultOrExc(result='a', exception=None),
            ResultOrExc(result=None, exception=EXPECTED_EXCEPTION),
            ResultOrExc(result='b', exception=None),
        ])

    def test_split_batch(self):
        """
        Tests an exception raised by an event method is returned to the
        correct AsyncResult.
        """
        f_a1 = self._actor.do_a(async=True)
        f_b1 = self._actor.do_b(async=True)
        f_a2 = self._actor.do_a(async=True)
        f_b2 = self._actor.do_b(async=True)
        f_a3 = self._actor.do_a(async=True)
        # Should see these batches:
        # Odd number:
        # [a, b, a, b, a] -> Split
        # [a, b] PENDING: [a, b, a] -> Split
        # Optimization: [b] gets pushed on front of pending batch.
        # [a] PENDING: [b, a, b, a] -> OK
        # Even number:
        # [b, a, b, a] -> Split
        # [b, a] PENDING: [b, a] -> OK
        # [b, a] -> OK
        self._actor._finish_side_effects = iter([
            SplitBatchAndRetry(),
            SplitBatchAndRetry(),
            None,
            SplitBatchAndRetry(),
            None,
            None,
        ])
        self.run_actor_loop()
        self.assertEqual(self._actor.batches, [
            ["sb", "a", "b", "a" ,"b", "a", "fb"],
            ["sb", "a", "b", "fb"],
            ["sb", "a", "fb"],
            ["sb", "b", "a", "b", "a", "fb"],
            ["sb", "b", "a", "fb"],
            ["sb", "b", "a", "fb"],
        ])

    def test_split_batch_exc(self):
        f_a = self._actor.do_a(async=True)
        f_exc = self._actor.do_exc(async=True)
        self._actor._finish_side_effects = iter([
            FinishException()
        ])
        self.run_actor_loop()
        # Gets reported to all callers, which is a bit ugly but something has
        # gone very wrong if we're not dealing with failures in _finish.
        self.assertTrue(f_a.ready())
        self.assertTrue(f_exc.ready())
        self.assertRaises(FinishException, f_a.get)
        self.assertRaises(FinishException, f_exc.get)

    def test_own_batch(self):
        f_a = self._actor.do_a(async=True)
        f_b = self._actor.do_b(async=True)
        f_own = self._actor.do_own_batch(async=True)
        f_a2 = self._actor.do_a(async=True)
        f_b2 = self._actor.do_b(async=True)

        self.run_actor_loop()

        self.assertTrue(f_a.ready())
        self.assertTrue(f_b.ready())
        self.assertTrue(f_own.ready())
        self.assertTrue(f_a2.ready())
        self.assertTrue(f_b2.ready())

        self.assertEqual(self._actor.batches, [
            ["sb", "a", "b", "fb"],
            ["sb", "own", "fb"],
            ["sb", "a", "b", "fb"],
        ])

    def test_blocking_call(self):
        self._actor.start()  # Really start it.
        self._actor.do_a(async=False)
        self.assertRaises(ExpectedException, self._actor.do_exc, async=False)

    def test_same_actor_call(self):
        """
        Test events can call each other as normal methods, bypassing the
        queue.
        """
        self._actor.start()  # really start it.
        self.assertEqual("c1c2",  self._actor.do_c(async=False))

    def test_loop_coverage(self):
        with mock.patch.object(self._actor, "_step", autospec=True) as m_step:
            m_step.side_effect = ExpectedException()
            self.assertRaises(ExpectedException, self._actor._loop)

    @mock.patch("gevent.sleep", autospec=True)
    def test_yield(self, m_sleep):
        self._actor.max_ops_before_yield = 2
        self._actor.start()  # Really start it.
        self._actor.do_a(async=False)
        self._actor.do_a(async=False)
        self._actor.do_a(async=False)
        m_sleep.assert_called_once_with(0.000001)

    def test_wait_and_check_no_input(self):
        actor.wait_and_check([])

    def test_wrap_msg_id(self):
        with mock.patch("calico.felix.actor.next_message_id"):
            with mock.patch("calico.felix.actor.Message", autospec=True) as m_msg:
                actor.next_message_id = sys.maxint
                self._actor.do_a(async=True)
                self._actor.do_a(async=True)

        self.assertEqual(
            [c for c in m_msg.mock_calls if c[0] == ""],
            [
                mock.call("M" + hex(sys.maxint)[2:], mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY, needs_own_batch=mock.ANY),
                mock.call("M0000000000000000", mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY, needs_own_batch=mock.ANY),
            ]
        )


class TestExceptionTracking(BaseTestCase):

    @mock.patch("calico.felix.actor._print_to_stderr", autospec=True)
    def test_exception(self, _print):
        """
        Test a simulated exception leak.
        """
        # Since the weak refs are cleaned up lazily, grab strong references to
        # any that are currently alive to prevent our baseline from changing
        # under us.
        refs_at_start = set([ref() for ref in
                             actor._tracked_refs_by_idx.values()])
        num_refs_at_start = len(refs_at_start)

        # Now do our test: leak a result with an exception attached.
        ar = actor.TrackedAsyncResult("foo")
        ar.set_exception(Exception())
        self.assertEqual(num_refs_at_start + 1, len(actor._tracked_refs_by_idx))
        del ar  # Enough to trigger cleanup in CPython, with exact ref counts.
        gc.collect()  # For PyPy, we have to force a cleanup
        self._m_exit.assert_called_once_with(1)
        self.assertTrue(_print.called)
        self.assertTrue("foo" in _print.call_args[0][0])
        self._m_exit.reset_mock()

        # Re-grab the set of references for comparison
        refs_at_end = set([ref() for ref in
                           actor._tracked_refs_by_idx.values()])
        num_refs_at_end = len(refs_at_end)
        self.assertEqual(refs_at_start, refs_at_end,
                         "%s exceptions may have been leaked: %s" %
                         (num_refs_at_end - num_refs_at_start,
                          actor._tracked_refs_by_idx))

    @mock.patch("calico.felix.actor._print_to_stderr", autospec=True)
    def test_no_exception(self, m_print):
        gc.collect()  # Make sure that all leaked refs are cleaned up
        num_refs_at_start = len(actor._tracked_refs_by_idx)
        ar = actor.TrackedAsyncResult("foo")
        ar.set("foo")
        del ar  # Enough to trigger cleanup in CPython, with exact ref counts.
        gc.collect()  # For PyPy, we have to force a cleanup
        self.assertFalse(self._m_exit.called)
        self.assertFalse(m_print.called)
        num_refs_at_end = len(actor._tracked_refs_by_idx)
        self.assertEqual(num_refs_at_start, num_refs_at_end)

    @mock.patch("calico.felix.actor._print_to_stderr", autospec=True)
    def test_real_actor_leaked_exc(self, m_print):
        """
        Really leak an exception-containing result returned via
        actor_message and check we exit.
        """
        self.assertFalse(self._m_exit.called)
        a = ActorForTesting()
        a.start()
        result = a.do_exc(async=True)
        del result  # We abandon the result so only the message has a ref.
        # Now block so that we know that the do_exc() must have been completed.
        a.do_a(async=False)
        gc.collect()  # For PyPy, we have to force a cleanup
        self._m_exit.assert_called_once_with(1)
        self._m_exit.reset_mock()


class ActorForTesting(actor.Actor):
    def __init__(self, qualifier=None):
        super(ActorForTesting, self).__init__(qualifier=qualifier)
        self.actions = []
        self._batch_actions = []
        self.batches = []
        self._finish_side_effects = (lambda _: None for _ in itertools.count())
        self.unreferenced = False
        self.on_unref_result = mock.Mock(autospec=AsyncResult)
        self.started = False

    def start(self):
        self.started = True
        return super(ActorForTesting, self).start()

    @actor_message()
    def do_a(self):
        self._batch_actions.append("a")
        assert self._current_msg.name == "do_a"
        self._maybe_yield()
        return "a"

    @actor_message()
    def do_b(self):
        self._batch_actions.append("b")
        assert self._current_msg.name == "do_b"
        return "b"

    @actor_message()
    def do_c(self):
        return self.do_c1() + self.do_c2()  # Same-actor calls skip queue.

    @actor_message()
    def do_c1(self):
        return "c1"

    @actor_message()
    def do_c2(self):
        return "c2"

    @actor_message(needs_own_batch=True)
    def do_own_batch(self):
        self._batch_actions.append("own")
        return "own"

    @actor_message()
    def do_exc(self):
        self._batch_actions.append("exc")
        raise EXPECTED_EXCEPTION

    def _start_msg_batch(self, batch):
        batch = super(ActorForTesting, self)._start_msg_batch(batch)
        self._batch_actions = []
        self._batch_actions.append("sb")
        return batch

    def _finish_msg_batch(self, batch, results):
        super(ActorForTesting, self)._finish_msg_batch(batch, results)
        assert self._current_msg is None
        self._batch_actions.append("fb")
        self.actions.extend(self._batch_actions)
        self.batches.append(list(self._batch_actions))
        self._batch_actions = []
        result = next(self._finish_side_effects)
        if isinstance(result, Exception):
            raise result

    # Note: this would normally be an actor_message but we bypass that and
    # return our own future.
    def on_unreferenced(self, async=None):
        assert not self.unreferenced
        self.unreferenced = True
        return self.on_unref_result


class FinishException(Exception):
    pass


EXPECTED_EXCEPTION = ExpectedException()
