# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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

import logging
import itertools
from contextlib import nested

from gevent.event import AsyncResult
import mock
from calico.felix.actor import actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.test.base import BaseTestCase
from calico.felix import actor


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
        Tests statting the actor starts its greenlet.
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

    def test_blocking_call(self):
        self._actor.start()  # Really start it.
        self._actor.do_a(async=False)
        self.assertRaises(ExpectedException, self._actor.do_exc,  async=False)

    def test_same_actor_call(self):
        """
        Test events can call each other as normal methods, bypassing the
        queue.
        """
        self._actor.start()  # really start it.
        self.assertEqual("c1c2",  self._actor.do_c(async=False))

    def test_full_queue(self):
        eq = self._actor._event_queue
        with nested(mock.patch.object(eq, "full", autospec=True),
                    mock.patch.object(eq, "put", autospec=True)) as \
                (m_full, m_put):
            m_full.return_value = True
            self._actor.do_a(async=True)
            self.assertTrue(m_put.call_args[1]["block"])
            self.assertEqual(m_put.call_args[1]["timeout"], 60)

    def test_loop_coverage(self):
        with mock.patch.object(self._actor, "_step", autospec=True) as m_step:
            m_step.side_effect = ExpectedException()
            self.assertRaises(ExpectedException, self._actor._loop)

    def test_batch_delay(self):
        self._actor.batch_delay = 1
        with mock.patch("gevent.sleep", autospec=True) as m_sleep:
            self._actor.do_a(async=True)
            self.step_actor(self._actor)
            m_sleep.assert_called_once_with(1)

    @mock.patch("gevent.sleep", autospec=True)
    def test_yield(self, m_sleep):
        self._actor.max_ops_before_yield = 2
        self._actor.start()  # Really start it.
        self._actor.do_a(async=False)
        self._actor.do_a(async=False)
        self._actor.do_a(async=False)
        m_sleep.assert_called_once_with()

    def test_wait_and_check_no_input(self):
        actor.wait_and_check([])


class TestExcpetionTracking(BaseTestCase):
    def test_exception(self):
        ar = actor.TrackedAsyncResult("foo")
        ar.set_exception(Exception())
        del ar  # Enough to trigger cleanup in CPython, with exact ref counts.
        self._m_exit.assert_called_once_with(1)
        self._m_exit.reset_mock()

    def test_no_exception(self):
        ar = actor.TrackedAsyncResult("foo")
        ar.set("foo")
        del ar  # Enough to trigger cleanup in CPython, with exact ref counts.
        self.assertFalse(self._m_exit.called)


class ActorForTesting(actor.Actor):
    def __init__(self, queue_size=None, qualifier=None):
        super(ActorForTesting, self).__init__(queue_size=queue_size,
                                              qualifier=qualifier)
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

    @actor_event
    def do_a(self):
        self._batch_actions.append("a")
        assert self._current_msg.name == "do_a"
        self._maybe_yield()
        return "a"

    @actor_event
    def do_b(self):
        self._batch_actions.append("b")
        assert self._current_msg.name == "do_b"
        return "b"

    @actor_event
    def do_c(self):
        return self.do_c1() + self.do_c2()  # Same-actor calls skip queue.

    @actor_event
    def do_c1(self):
        return "c1"

    @actor_event
    def do_c2(self):
        return "c2"

    @actor_event
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

    # Note: this would normally be an actor_event but we bypass that and
    # return our own future.
    def on_unreferenced(self, async=None):
        assert not self.unreferenced
        self.unreferenced = True
        return self.on_unref_result


class ExpectedException(Exception):
    pass


class FinishException(Exception):
    pass


EXPECTED_EXCEPTION = ExpectedException()
