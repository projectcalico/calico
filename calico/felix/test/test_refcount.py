# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
from calico.felix.actor import actor_event
from calico.felix.refcount import ReferenceManager, RefCountedActor, LIVE, \
    STOPPING
from calico.felix.test.base import BaseTestCase
from calico.felix.test.test_actor import ActorForTesting
from gevent.event import AsyncResult
import mock

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


class RefMgrForTesting(ReferenceManager):
    def __init__(self):
        super(RefMgrForTesting, self).__init__()
        self.idx = 0
        self.ref_actions = []

    def _create(self, object_id):
        a = RefCountedActorForTesting(self.idx, self.ref_actions)
        self.idx += 1
        return a

    def _on_object_started(self, object_id, obj):
        self.ref_actions.append(("rm", "activate %s" % obj.idx))
        obj.active = True
        obj.on_referenced(async=True)

    @actor_event
    def on_object_cleanup_complete(self, *args, **kwargs):
        self.ref_actions.append(("rm", "recv cleanup complete"))
        super(RefMgrForTesting, self).on_object_cleanup_complete(*args,
                                                                 **kwargs)


class RefCountedActorForTesting(RefCountedActor, ActorForTesting):
    def __init__(self, idx, ref_actions):
        super(RefCountedActorForTesting, self).__init__()
        self.idx = idx
        self.ref_actions = ref_actions

    def push_action(self, action):
        self.ref_actions.append((self.idx, action))

    @actor_event
    def on_referenced(self):
        self.push_action("on_referenced")
        self._notify_ready()

    @actor_event
    def on_unreferenced(self):
        self.push_action("on_unreferenced")
        super(RefCountedActorForTesting, self).on_unreferenced()

    def __str__(self):
        return "RefCountedActorForTesting<%s>" % self.idx