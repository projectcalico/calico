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

import collections
import functools

import logging
import weakref
from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)

# States that a reference-counted actor can be in.

# Initial state, created but not yet started.  May stay in this state if
# we're waiting for a previous actor with same ID to clean up.
CREATED = "created"
# We told the actor to start but haven't heard back from it via
# on_object_startup_complete() yet.
STARTING = "starting"
# We've heard back from the actor, it's live and ready to be distributed to
# referrers.
LIVE = "live"
# We've told the actor to stop, there are no more references to it in the wild
# and we'll never activate it again.
STOPPING = "stopping"


class ReferenceManager(Actor):
    """
    Actor that manages the life cycle of a collection of other Actors
    by name. Users can request a reference to an actor by name using
    get_and_incref() and then they must return it by calling decref().

    Consecutive calls to incref return the same actor. Actors are only
    cleaned up when their reference count hits zero.

    Users who obtain a reference through get_and_incref() must stop
    using the reference before calling decref().
    """

    def __init__(self, qualifier=None):
        super(ReferenceManager, self).__init__(qualifier=qualifier)
        self.objects_by_id = {}
        self.stopping_objects_by_id = collections.defaultdict(set)
        self.pending_ref_callbacks = collections.defaultdict(set)

    @actor_message()
    def get_and_incref(self, object_id, callback=None):
        """
        Acquire a reference to a ref-counted Actor, returns via callback.
        :param object_id: opaque ID of the Actor to retrieve, must be hashable.
        :param callback: callback, receives the object_id and object as args.
        """
        _log.debug("Request for object %s", object_id)
        assert object_id is not None

        if object_id not in self.objects_by_id:
            _log.info("%s object with id %s didn't exist, creating it.",
                      self.name, object_id)
            obj = self._create(object_id)
            obj._manager = weakref.proxy(self)
            obj._id = object_id
            self.objects_by_id[object_id] = obj
        else:
            obj = self.objects_by_id[object_id]
            _log.info("%s object with id %s existed with ref count %d in "
                      "state %s; increffing it.", self.name, object_id,
                      obj.ref_count, obj.ref_mgmt_state)

        if callback:
            self.pending_ref_callbacks[object_id].add(callback)
        obj.ref_count += 1
        _log.debug("Reference count for %s object %s is %d",
                   self.name, object_id, obj.ref_count)

        # Depending on state of object, may need to start it or immediately
        # call back.
        self._maybe_start(object_id)
        self._maybe_notify_referrers(object_id)

    @actor_message()
    def on_object_startup_complete(self, object_id, obj):
        """
        Callback from a ref-counted object to tell us that it has completed
        its startup.

        The ref-counted actor must make this callback once it is ready to
        be referenced unless it receives an on_unreferenced() message,
        after which calls to this method from that actor are allowed but
        ignored.
        """
        _log.debug("Object startup complete for %s", object_id)
        if self.objects_by_id.get(object_id) is not obj:
            _log.info("Ignoring on_object_startup_complete for old instance:"
                      "%r is not %r", self.objects_by_id.get(object_id), obj)
            return
        if obj.ref_mgmt_state != STARTING:
            # We can hit this case if the object was starting and we asked it
            # to shut down before we received the callback.
            _log.info("Ignoring on_object_startup_complete for instance "
                      "in state %s", obj.ref_mgmt_state)
            return
        _log.info("Object %s startup completed", object_id)
        obj.ref_mgmt_state = LIVE
        self._maybe_notify_referrers(object_id)

    @actor_message()
    def decref(self, object_id):
        """
        Return a reference and garbage-collect the backing actor if it is no
        longer referenced elsewhere.
        """
        assert object_id in self.objects_by_id
        obj = self.objects_by_id[object_id]
        obj.ref_count -= 1
        assert obj.ref_count >= 0, "Ref count dropped below 0.s"
        _log.debug("Reference count for %s object %s is %d",
                   self.name, object_id, obj.ref_count)
        if obj.ref_count == 0:
            _log.debug("No more references to object with id %s", object_id)
            if obj.ref_mgmt_state == CREATED:
                _log.debug("%s was never started, discarding", obj)
            else:
                _log.debug("%s is running, cleaning it up", obj)
                obj.ref_mgmt_state = STOPPING
                obj.on_unreferenced(async=True)
                self.stopping_objects_by_id[object_id].add(obj)
            self.objects_by_id.pop(object_id)
            self.pending_ref_callbacks.pop(object_id, None)

    @actor_message()
    def on_object_cleanup_complete(self, object_id, obj):
        """
        Callback from ref-counted actor to tell us that it has finished
        its cleanup and it is safe to clean up our state and start new
        instances with the same ID.
        """
        _log.debug("Cleanup complete for %s, removing it from map", obj)
        self.stopping_objects_by_id[object_id].discard(obj)
        if not self.stopping_objects_by_id[object_id]:
            del self.stopping_objects_by_id[object_id]
            # May have unblocked start of new object...
            self._maybe_start(object_id)

    def _maybe_start_all(self):
        _log.debug("Checking all objects to see if they can be started")
        for obj_id in self.objects_by_id:
            self._maybe_start(obj_id)

    def _maybe_start(self, obj_id):
        """
        Starts the actor with the given ID if it is present and there
        are no pending cleanups for that ID.

        Subclasses may override this method to place additional
        pre-requisites on starting the object.  They should call
        this implementation if they are happy for the start to
        proceed.

        If the subclass chooses to block startup, it must later call
        this method (or the convenience method _maybe_start_all())
        when it wants to allow startup to proceed.
        """
        obj = self.objects_by_id.get(obj_id)
        if (obj and
                obj.ref_mgmt_state == CREATED and
                obj_id not in self.stopping_objects_by_id):
            _log.info("%s Starting object %s", self.name, obj_id)
            obj.ref_mgmt_state = STARTING
            obj.start()
            self._on_object_started(obj_id, obj)
        elif obj_id in self.stopping_objects_by_id:
            _log.info("Cannot start object %s because we're waiting for an "
                      "object with that ID to stop.", obj_id)
        elif obj and obj.ref_mgmt_state != CREATED:
            _log.debug("Not starting object %s; it's already started", obj_id)

    def _maybe_notify_referrers(self, object_id):
        """
        If the object with the given ID is LIVE, notify any pending referrers.
        """
        _log.debug("Checking whether we can notify referrers for %s",
                   object_id)
        obj = self.objects_by_id.get(object_id)
        if obj and obj.ref_mgmt_state == LIVE:
            _log.info("Object %s is LIVE, notifying referrers", object_id)
            for cb in self.pending_ref_callbacks[object_id]:
                cb(object_id, obj)
            self.pending_ref_callbacks.pop(object_id, None)
        else:
            _log.info("Cannot notify referrers for %s; object state: %s",
                      object_id, obj.ref_mgmt_state)

    def _on_object_started(self, obj_id, obj):
        """
        To be overriden by subclasses, called to initialize the actor
        after it has been started but before it is returned to referrers.

        This method should set in motion whatever messages need to be sent to
        eventually trigger a call to on_object_startup_complete().
        """
        raise NotImplementedError()  # pragma nocover

    def _create(self, object_id):
        """
        To be overriden by subclasses.

        :returns: A new instance of the actor that this manager is to track.
                  The instance should not be started.
        """
        raise NotImplementedError()  # pragma nocover

    def _is_starting_or_live(self, obj_id):
        return (obj_id in self.objects_by_id and
                self.objects_by_id[obj_id].ref_mgmt_state in (STARTING, LIVE))


class RefHelper(object):
    """
    Helper class for a clients of a ReferenceManager that need to
    acquire a potentially-changing set of references before making
    progress.

    Note: this helper piggy-backs on the actor's message queue
    in order to receive callbacks from the ReferenceManager.
    """

    def __init__(self, actor, ref_mgr, ready_callback):
        """
        Constructor.
        :param actor: Actor instance; this object piggy-backs on the Actor's
            message queue.
        :param ready_callback: Callback to execute on the actor's greenlet
            when all the objects in the set have been acquired.  Should
            be a simple bound method, it will be called from the
            on_ref_acquired @actor_message of this object.
        """
        self._actor = actor
        """Actor that we belong to, we'll use its queue for callbacks."""
        self._ref_mgr = ref_mgr
        """Ref manager to acquire references from."""
        self._ready_callback = ready_callback
        """Callback to issue when we acquire all the references required."""

        self.required_refs = set()
        """Set of IDs of the references that we've been asked for."""
        self.pending_increfs = set()
        """
        Set of IDs of references for which we have an outstanding incref
        request.
        """
        self.acquired_refs = {}
        """
        Mapping from object ID to object that we've acquired.
        """

    def replace_all(self, new_obj_ids):
        """
        Change the set of references we require to the given set.
        """
        _log.debug("Setting required refs to %s", new_obj_ids)
        for obj_id in new_obj_ids:
            self.acquire_ref(obj_id)
        for obj_id in [r for r in self.required_refs if r not in new_obj_ids]:
            self.discard_ref(obj_id)

    def acquire_ref(self, obj_id):
        """
        Add the given ID to the set of objects that we want to acquire.
        Idempotent; does nothing if the ID is already in the set.
        """
        if obj_id not in self.required_refs:
            # Immediately record that we require this ref.
            self.required_refs.add(obj_id)
            if obj_id not in self.pending_increfs:
                # We're not already asking for the ref, request it.
                _log.debug("Increffing object %s", obj_id)
                cb = functools.partial(self.on_ref_acquired, async=True)
                self.pending_increfs.add(obj_id)
                self._ref_mgr.get_and_incref(obj_id, callback=cb, async=True)

    def discard_ref(self, obj_id):
        """
        Discard the reference identified by ID.  Idempotent; does nothing
        if the reference wasn't present.
        """
        if obj_id in self.required_refs:
            _log.debug("Discarding object %s", obj_id)
            # Immediately record that we no longer want the ref and throw it
            # away (if we've acquired it).
            self.required_refs.remove(obj_id)
            self.acquired_refs.pop(obj_id, None)
            if obj_id not in self.pending_increfs:
                # Only decref after we've actually acquired the ref.  This
                # avoids a lot of complexity in managing multiple outstanding
                # callbacks.
                _log.debug("Decreffing object %s", obj_id)
                self._ref_mgr.decref(obj_id, async=True)

    def discard_all(self):
        """
        Discards all references.
        """
        for obj_id in list(self.required_refs):
            self.discard_ref(obj_id)

    @actor_message()
    def on_ref_acquired(self, obj_id, obj):
        was_ready = self.ready
        self.pending_increfs.discard(obj_id)
        if obj_id in self.required_refs:
            # Still required, record it.
            _log.debug("Reference %s acquired; still required", obj_id)
            self.acquired_refs[obj_id] = obj
        else:
            # Deleted while we were waiting.
            _log.debug("Object %s was discarded while waiting for its ref",
                       obj_id)
            self._ref_mgr.decref(obj_id, async=True)
        now_ready = self.ready
        if not was_ready and now_ready:
            _log.debug("Acquired all references, calling ready callback")
            self._ready_callback()

    def iteritems(self):
        """
        :returns: iterator over pairs of the currently valid references. Not
                  safe for concurrent modification of the set of IDs.
        """
        return self.acquired_refs.iteritems()

    @property
    def ready(self):
        return len(self.required_refs) == len(self.acquired_refs)

    def __getattr__(self, item):
        """
        Passes through getattr requests to the Actor to allow us to
        use @actor_message.
        """
        try:
            return super(RefHelper, self).__getattr__(item)
        except AttributeError:
            return getattr(self._actor, item)


class RefCountedActor(Actor):
    def __init__(self, qualifier=None):
        super(RefCountedActor, self).__init__(qualifier=qualifier)

        # These fields are owned by the ReferenceManager.
        self._manager = None
        self._id = None
        self.ref_mgmt_state = CREATED
        self.ref_count = 0

    def _notify_ready(self):
        """
        Utility method, to be called by subclass once its startup
        is complete.  Notifies the manager.
        """
        _log.debug("Notifying manager that %s is ready", self)
        self._manager.on_object_startup_complete(self._id, self, async=True)

    @actor_message()
    def on_unreferenced(self):
        """
        Message sent by manager to tell this object to clean itself up
        for it can no longer be referenced.

        Must, eventually, result in a call to self._notify_cleanup_complete().

        This implementation immediately calls self._notify_cleanup_complete()
        """
        _log.debug("Default on_unreferenced() call, notifying cleanup done")
        self._notify_cleanup_complete()

    def _notify_cleanup_complete(self):
        """
        Utility method, to be called by subclass once its cleanup
        is complete.  Notifies the manager.
        """
        _log.debug("Notifying manager that %s is done cleaning up", self)
        self._manager.on_object_cleanup_complete(self._id, self, async=True)
