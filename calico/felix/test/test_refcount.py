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

import logging
from calico.felix.actor import actor_message
from calico.felix.refcount import ReferenceManager, RefCountedActor, \
    RefHelper, LIVE, STOPPING
from calico.felix.test.base import BaseTestCase
from calico.felix.test.test_actor import ActorForTesting
from gevent.event import AsyncResult

_log = logging.getLogger(__name__)


class TestReferenceManager(BaseTestCase):
    def setUp(self):
        super(TestReferenceManager, self).setUp()
        self._rm = RefMgrForTesting()
        self._rm.start()

    def call_via_cb(self, fn, *args, **kwargs):
        result = AsyncResult()
        fn(callback=lambda *a: result.set(a),
           *args, **kwargs)
        return result.get(timeout=5)

    def test_multiple_gets_receive_same_obj(self):
        obj_id_1, obj_1 = self.call_via_cb(self._rm.get_and_incref, "foo",
                                           async=True)
        obj_id_2, obj_2 = self.call_via_cb(self._rm.get_and_incref, "foo",
                                           async=True)
        self.assertEqual("foo", obj_id_1)
        self.assertEqual("foo", obj_id_2)
        self.assertTrue(obj_1 is obj_2)
        self.assertTrue(isinstance(obj_1, ActorForTesting))

    def test_ref_counting(self):
        _, obj = self.call_via_cb(self._rm.get_and_incref, "foo", async=True)
        self.assertEqual(obj.ref_count, 1)
        self.assertEqual(obj.ref_mgmt_state, LIVE)
        self.assertTrue(self._rm._is_starting_or_live("foo"))
        _, obj = self.call_via_cb(self._rm.get_and_incref, "foo", async=True)
        self.assertEqual(obj.ref_count, 2)
        self._rm.decref("foo", async=False)
        self.assertEqual(obj.ref_count, 1)
        self._rm.decref("foo", async=False)
        self.assertEqual(obj.ref_count, 0)
        self.assertEqual(obj.ref_mgmt_state, STOPPING)

        # Now the object should be being cleaned up, recreate it.
        _, new_obj = self.call_via_cb(self._rm.get_and_incref, "foo",
                                      async=True)
        self.assertEqual(new_obj.ref_count, 1)
        self.assertTrue(obj is not new_obj)
        self.assertEqual(new_obj.ref_mgmt_state, LIVE)
        self.assertTrue(self._rm._is_starting_or_live("foo"))

        self.assertEqual(self._rm.ref_actions, [
            # First obj, gets increffed twice but only told about it once.
            ("rm", "activate 0"),
            (0, 'on_referenced'),
            # Then it gets told about its demise.
            (0, 'on_unreferenced'),
            # RefMgr waits until it hears about the completion before
            # activating new one.
            ("rm", "recv cleanup complete"),
            ("rm", "activate 1"),
            (1, 'on_referenced'),
        ])

    def test_decref_while_starting(self):
        # Start creating a reference, but then decref it before it's LIVE
        obj = self._rm.get_and_incref("foo", async=True)
        self._rm.decref("foo", async=True)

        # Let all the actors run
        _, obj = self.call_via_cb(self._rm.get_and_incref, "bar", async=True)

    def test_double_recreate_while_cleaning_up(self):
        def record_get(obj_id, obj):
            self._rm.ref_actions.append(("client",
                                         "received ref %s" % obj.idx))

        # These requests will get queued up because we don't give the RefMgr
        # a chance to run.
        self._rm.get_and_incref("foo", callback=record_get, async=True)
        self._rm.decref("foo", async=True)
        self._rm.get_and_incref("foo", callback=record_get, async=True)
        self._rm.decref("foo", async=True)
        self._rm.get_and_incref("foo", callback=record_get, async=True)
        self._rm.decref("foo", async=True)
        # Drain the queue
        _, obj = self.call_via_cb(self._rm.get_and_incref, "foo", async=True)

        self.assertEqual(self._rm.ref_actions, [
            # No object to start with so immediately gets started.
            ("rm", "activate 0"),
            (0, 'on_referenced'),
            # Then gets removed again.  No callbacks to record_get because
            # the decref is ahead of the startup_complete callback.
            # Actor 1-2 is created and deleted without ever being started
            # because it's blocked behind the cleanup of 0.
            (0, 'on_unreferenced'),
            # Actor 2 gets created.
            ('rm', 'recv cleanup complete'),
            ("rm", "activate 3"),
            (3, 'on_referenced')
        ])


class TestRefHelper(TestReferenceManager):
    def setUp(self):
        super(TestRefHelper, self).setUp()
        self._rh = RefHelper(self._rm,
                             self._rm,
                             self._rm.ready_callback)

    def test_no_refs(self):
        # With no references, we're ready but haven't been notified
        self.assertFalse(self._rm._ready_called)
        self.assertTrue(self._rh.ready)

        # Discarding non-existent references is allowed
        self._rh.discard_ref("foo")

    def test_acquire_discard_1(self):
        # Acquire a reference to 'foo' - it won't be ready immediately
        self._rh.acquire_ref("foo")
        self.assertFalse(self._rm._ready_called)
        self.assertFalse(self._rh.ready)

        # Spin the actor framework - we become ready
        _, obj = self.call_via_cb(self._rm.get_and_incref, "bar", async=True)
        self.assertTrue(self._rm._ready_called)
        self.assertTrue(self._rh.ready)
        self.assertEqual(next(self._rh.iteritems())[0], "foo")

        # Acquiring an already-acquired reference is idempotent
        self._rh.acquire_ref("foo")
        self.assertTrue(self._rh.ready)

        # Discard the reference
        self._rh.discard_ref("foo")
        _, obj = self.call_via_cb(self._rm.get_and_incref, "baz", async=True)
        self.assertTrue(self._rh.ready)

    def test_sync_acquire_discard(self):
        # Acquire a reference and discard it before it's become ready
        self._rh.acquire_ref("foo")
        self.assertFalse(self._rh.ready)

        self._rh.discard_ref("foo")
        self.assertTrue(self._rh.ready)

        # Spin the actor framework
        _, obj = self.call_via_cb(self._rm.get_and_incref, "bar", async=True)

    def test_acquire_discard_2(self):
        # Acquire two references
        self._rh.acquire_ref("foo")
        _, obj = self.call_via_cb(self._rm.get_and_incref, "bar", async=True)
        self._rh.acquire_ref("baz")
        self.assertFalse(self._rh.ready)
        _, obj = self.call_via_cb(self._rm.get_and_incref, "bar2", async=True)
        acq_ids = list(key for key, value in self._rh.iteritems())
        self.assertItemsEqual(acq_ids, ["foo", "baz"])
        self.assertTrue(self._rh.ready)

        # Discard them all!
        self._rh.discard_all()


class RefMgrForTesting(ReferenceManager):
    def __init__(self):
        super(RefMgrForTesting, self).__init__()
        self.idx = 0
        self.ref_actions = []
        self._ready_called = False

    def _create(self, object_id):
        a = RefCountedActorForTesting(self.idx, self.ref_actions)
        self.idx += 1
        return a

    def _on_object_started(self, object_id, obj):
        self.ref_actions.append(("rm", "activate %s" % obj.idx))
        obj.active = True
        obj.on_referenced(async=True)

    @actor_message()
    def on_object_cleanup_complete(self, *args, **kwargs):
        self.ref_actions.append(("rm", "recv cleanup complete"))
        super(RefMgrForTesting, self).on_object_cleanup_complete(*args,
                                                                 **kwargs)

    @actor_message()
    def ready_callback(self):
        self._ready_called = True


class RefCountedActorForTesting(RefCountedActor, ActorForTesting):
    def __init__(self, idx, ref_actions):
        super(RefCountedActorForTesting, self).__init__()
        self.idx = idx
        self.ref_actions = ref_actions

    def push_action(self, action):
        self.ref_actions.append((self.idx, action))

    @actor_message()
    def on_referenced(self):
        self.push_action("on_referenced")
        self._notify_ready()

    @actor_message()
    def on_unreferenced(self):
        self.push_action("on_unreferenced")
        super(RefCountedActorForTesting, self).on_unreferenced()

    def __str__(self):
        return "RefCountedActorForTesting<%s>" % self.idx
