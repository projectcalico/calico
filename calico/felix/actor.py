# -*- coding: utf-8 -*-
# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
felix.actor
~~~~~~~~~~~

A queue-based Actor framework that supports efficient handling of
batches of messages.  Each Actor instance has its own greenlet
and a queue of pending messages.  Messages are sent by making calls
to a method decorated by the @actor_message decorator.

When an actor_message-decorated method is called from another greenlet
the method call is wrapped up as a Message object and put on the
queue.

Note: callers must specify the async=True/False argument when calling
a actor_message-decorated method.  If async=True is passed, the method
returns an AsyncResult.  If async=False is passed, the method blocks
until the result is available and returns it as-is. As a convenience,
Actors may call their own decorated methods without passing async=...;
such calls are treated as normal, synchronous method calls.

Each time it is scheduled, the main loop of the Actor

* pulls all pending messages off the queue as a batch
* notifies the subclass that a batch is about to start via
  _start_msg_batch()
* executes each of the actor_message method calls from the batch in order
* notifies the subclass that the batch is finished by calling
  _finish_msg_batch()
* publishes the results from the batch via AsyncResults, allowing
  callers to check for exceptions or receive a result.

Simple actors
~~~~~~~~~~~~~

A simple Actor may ignore the start/finish_msg_batch calls and do
all its work in the actor_message-decorated methods, ensuring that
all its invariants are restored by the end of each call.

Supporting batches
~~~~~~~~~~~~~~~~~~

For an actor that can handle a batch more efficiently, it may
initialize some per-batch state in the start_msg_batch function,
update the state from its actor_message methods and then "commit"
the state in _finish_msg_batch().

Since moving the commit stage to _finish_msg_batch() can make
it hard to report errors to the correct AsyncResult, the framework
supports the ability to split a batch of work and retry it from
the beginning.  To make use of that function, an Actor must:

* take part in batching
* have actor_message methods that only affect the per-batch state
  (i.e. it must defer its side effects to the _finish_msg_batch()
  method)
* raise SplitBatchAndRetry from its _finish_msg_batch() method,
  ensuring, of course, that it did not leave any resources
  partially-modified.

Thread safety
~~~~~~~~~~~~~

While the framework makes it easy to avoid shared state, there are
some gotchas:

* Using the async=False feature blocks the current greenlet until the
  one it is calling into returns a result.  This can also cause deadlock
  if there are call cycles.

* We deliberately use unbounded queues for queueing up messages between
  actors. Bounding the queues would allow deadlock since the sending actor
  can block on a full queue and the receiving actor may be blocked on the
  queue of the sender, trying to send another message.

Unhandled Exceptions
~~~~~~~~~~~~~~~~~~~~

The framework keeps track of pending AsyncResults and tries to detect
callbacks that were GCed with a pending exception.  If is detects such
an exception, it terminates the process on the assumption that
an unhandled exception implies a bug and may leave the system in an
inconsistent state.

"""
import collections
import functools
import gevent
import gevent.local
import logging
import os
import sys
import traceback
import uuid
import weakref

from gevent.event import AsyncResult
from gevent.queue import Queue


_log = logging.getLogger(__name__)


ResultOrExc = collections.namedtuple("ResultOrExc", ("result", "exception"))

# Local storage to allow diagnostics.
actor_storage = gevent.local.local()


class Actor(object):
    """
    Class that contains a queue and a greenlet serving that queue.
    """

    batch_delay = None
    """
    Delay in seconds imposed after receiving first message before processing
    the messages in a batch.  Higher values encourage batching.
    """

    max_ops_before_yield = 10000
    """Number of calls to self._maybe_yield before it yields"""

    def __init__(self, qualifier=None):
        self._event_queue = Queue()
        self.greenlet = gevent.Greenlet(self._loop)
        self._op_count = 0
        self._current_msg = None
        self.started = False

        # Message being processed; purely for logging.
        self.msg_uuid = None

        # Logging parameters
        self.qualifier = qualifier
        if qualifier:
            self.name = "%s(%s)" % (self.__class__.__name__, qualifier)
        else:
            self.name = self.__class__.__name__

    # TODO: Can we just start the greenlet always?
    # There is some craziness about actors that are in CREATED state, where
    # pending a previous iteration shutting down.
    # PLW: I agree that the answer here is probably no, but not sure if we
    # could somehow simplify the code in this area.
    def start(self):
        assert not self.greenlet, "Already running"
        _log.debug("Starting %s", self)
        self.started = True
        self.greenlet.start()
        return self

    def _loop(self):
        """
        Main greenlet loop, repeatedly runs _step().  Doesn't return normally.
        """
        actor_storage.name = self.name
        actor_storage.msg_uuid = None

        try:
            while True:
                self._step()
        except:
            _log.exception("Exception killed %s", self)
            raise

    def _step(self):
        """
        Run one iteration of the event loop for this actor.  Mainly
        broken out to allow the UTs to single-step an Actor.

        It also has the beneficial side effect of introducing a new local
        scope so that our variables die before we block next time.
        """
        # Block waiting for work.
        msg = self._event_queue.get()
        actor_storage.msg_uuid = msg.uuid

        batch = [msg]
        batches = []

        if not msg.needs_own_batch:
            # Try to pull some more work off the queue to combine into a
            # batch.
            if self.batch_delay:
                # If requested by our subclass, delay the start of the batch to
                # allow more work to accumulate.
                gevent.sleep(self.batch_delay)
            while not self._event_queue.empty():
                # We're the only ones getting from the queue so this should
                # never fail.
                msg = self._event_queue.get_nowait()
                if msg.needs_own_batch:
                    if batch:
                        batches.append(batch)
                    batches.append([msg])
                    batch = []
                else:
                    batch.append(msg)
        if batch:
            batches.append(batch)

        num_splits = 0
        while batches:
            # Process the first batch on our queue of batches.  Invariant:
            # we'll either process this batch to completion and discard it or
            # we'll put all the messages back into the batch queue in the same
            # order but with a first batch that is half the size and the
            # rest of its messages in the second batch.
            batch = batches.pop(0)
            # Give subclass a chance to filter the batch/update its state.
            batch = self._start_msg_batch(batch)
            assert batch is not None, "_start_msg_batch() should return batch."
            results = []  # Will end up same length as batch.
            for msg in batch:
                _log.debug("Message %s recd by %s from %s, queue length %d",
                           msg, msg.recipient, msg.caller,
                           self._event_queue.qsize())
                self._current_msg = msg
                try:
                    # Actually execute the per-message method and record its
                    # result.
                    result = msg.method()
                except BaseException as e:
                    _log.exception("Exception processing %s", msg)
                    results.append(ResultOrExc(None, e))
                else:
                    results.append(ResultOrExc(result, None))
                finally:
                    self._current_msg = None
            try:
                # Give subclass a chance to post-process the batch.
                _log.debug("Finishing message batch")
                self._finish_msg_batch(batch, results)
            except SplitBatchAndRetry:
                # The subclass couldn't process the batch as is (probably
                # because a failure occurred and it couldn't figure out which
                # message caused the problem).  Split the batch into two and
                # re-run it.
                _log.warn("Splitting batch to retry.")
                self.__split_batch(batch, batches)
                num_splits += 1  # For diags.
                continue
            except BaseException as e:
                # Most-likely a bug.  Report failure to all callers.
                _log.exception("_finish_msg_batch failed.")
                results = [(None, e)] * len(results)

            # Batch complete and finalized, set all the results.
            assert len(batch) == len(results)
            for msg, (result, exc) in zip(batch, results):
                for future in msg.results:
                    if exc is not None:
                        future.set_exception(exc)
                    else:
                        future.set(result)
        if num_splits > 0:
            _log.warn("Split batches complete. Number of splits: %s",
                      num_splits)

    @staticmethod
    def __split_batch(current_batch, remaining_batches):
        """
        Splits batch in half and prepends it to the list of remaining
        batches. Modifies remaining_batches in-place.

        :param list[Message] current_batch: list of messages that's currently
               being processed.
        :param list[list[Message]] remaining_batches: list of batches
               still to process.
        """
        assert len(current_batch) > 1, "Batch too small to split"
        # Split the batch.
        split_point = len(current_batch) // 2
        _log.debug("Split-point = %s", split_point)
        first_half = current_batch[:split_point]
        second_half = current_batch[split_point:]
        if remaining_batches and not remaining_batches[0][0].needs_own_batch:
            # Optimization: there's another batch already queued and
            # it also contains batchable messages push the second
            # half of this batch onto the front of that one.
            _log.debug("Split batch and found a subsequent batch, "
                       "coalescing with that.")
            next_batch = remaining_batches[0]
            next_batch[:0] = second_half
        else:
            _log.debug("Split batch but cannot prepend to next batch, adding "
                       "both splits to start of queue.")
            remaining_batches[:0] = [second_half]
        remaining_batches[:0] = [first_half]

    def _start_msg_batch(self, batch):
        """
        Called before processing a batch of messages to give subclasses
        a chance to filter the batch.  Implementations must ensure that
        every AsyncResult in the batch is correctly set.  Usually, that
        means combining them into one list.

        It is usually easier to build up a batch of changes to make in the
        @actor_message-decorated methods and then process them in
        _finish_msg_batch().

        Intended to be overridden.  This implementation simply returns the
        input batch.

        :param list[Message] batch:
        """
        return batch

    def _finish_msg_batch(self, batch, results):
        """
        Called after a batch of events have been processed from the queue
        before results are set.

        Intended to be overridden.  This implementation does nothing.

        Exceptions raised by this method are propagated to all messages in the
        batch, overriding the existing results.  It is recommended that the
        implementation catches appropriate exceptions and maps them back
        to the correct entry in results.

        :param list[ResultOrExc] results: Pairs of (result, exception)
            representing the result of each message-processing function.
            Only one of the values is set.  Updates to the list alter the
            result send to any waiting listeners.
        :param list[Message] batch: The input batch, always the same length as
            results.
        """
        pass

    def _maybe_yield(self):
        """
        With some probability, yields processing to another greenlet.
        (Utility method to be called from the actor's greenlet during
        long-running operations.)
        """
        self._op_count += 1
        if self._op_count >= self.max_ops_before_yield:
            gevent.sleep()
            self._op_count = 0

    def __str__(self):
        return self.__class__.__name__ + "<queue_len=%s,live=%s,msg=%s>" % (
            self._event_queue.qsize(),
            bool(self.greenlet),
            self._current_msg
        )


class SplitBatchAndRetry(Exception):
    """
    Exception that may be raised by _finish_msg_batch() to cause the
    batch of messages to be split, each message to be re-executed and
    then the smaller batches delivered to _finish_msg_batch() again.
    """
    pass


def wait_and_check(async_results):
    for r in async_results:
        r.get()


_refs = {}
_ref_idx = 0


class Message(object):
    """
    Message passed to an actor.
    """
    def __init__(self, method, results, caller_path, recipient,
                 needs_own_batch):
        self.uuid = uuid.uuid4().hex[:12]
        self.method = method
        self.results = results
        self.caller = caller_path
        self.name = method.func.__name__
        self.needs_own_batch = needs_own_batch
        self.recipient = recipient

    def __str__(self):
        data = ("%s (%s)" % (self.uuid, self.name))
        return data


class ExceptionTrackingRef(weakref.ref):
    """
    Specialised weak reference with a slot to hold an exception
    that was leaked.
    """

    # Note: superclass implements __new__ so we have to mimic its args
    # and have the callback passed in.
    def __init__(self, obj, callback):
        super(ExceptionTrackingRef, self).__init__(obj, callback)
        self.exception = None
        self.tag = None
        self.msg = None

        # Callback won't get triggered if we die before the object we reference
        # so stash a reference to this object, which we clean up when the
        # TrackedAsyncResult is GCed.
        global _ref_idx
        self.idx = _ref_idx
        _ref_idx += 1
        _refs[self.idx] = self

    def __str__(self):
        return (self.__class__.__name__ + "<%s/%s,exc=%s>" %
                (self.tag, self.idx, self.exception))


def _reap_ref(ref):
    """
    Called when a TrackedAsyncResult gets GCed.

    Looks for leaked exceptions.

    :param ExceptionTrackingRef ref: The ref that may contain a leaked
        exception.
    """
    _log.debug("Reaping %s", ref)
    assert isinstance(ref, ExceptionTrackingRef)
    del _refs[ref.idx]
    if ref.exception:
        _log.critical("TrackedAsyncResult %s was leaked with exception %r",
                      ref.msg, ref.exception)
        print >> sys.stderr, "TrackedAsyncResult %s was leaked with " \
                             "exception %r" % (ref.tag, ref.exception)

        # Called from the GC so we can't raise an exception, just die.
        _exit(1)


def _exit(rc):
    """
    Immediately terminates this process with the given return code.

    This function is mainly here to be mocked out in UTs.
    """
    os._exit(rc)  # pragma nocover


class TrackedAsyncResult(AsyncResult):
    """
    An AsyncResult that tracks if any exceptions are leaked.
    """
    def __init__(self, tag):
        super(TrackedAsyncResult, self).__init__()
        self.__ref = ExceptionTrackingRef(self, _reap_ref)
        self.__ref.tag = tag

    def set_msg(self, msg):
        self.__ref.msg = msg

    def set_exception(self, exception):
        self.__ref.exception = exception
        return super(TrackedAsyncResult, self).set_exception(exception)

    def get(self, block=True, timeout=None):
        try:
            result = super(TrackedAsyncResult, self).get(block=block,
                                                         timeout=timeout)
        finally:
            # Someone called get so any exception can't be leaked.  Discard it.
            self.__ref.exception = None
        return result


def actor_message(needs_own_batch=False):
    def decorator(fn):
        method_name = fn.__name__
        @functools.wraps(fn)
        def queue_fn(self, *args, **kwargs):
            # Get call information for logging purposes.
            calling_file, line_no, func, _ = traceback.extract_stack()[-2]
            calling_file = os.path.basename(calling_file)
            calling_path = "%s:%s:%s" % (calling_file, line_no, func)
            try:
                caller = "%s (processing %s)" % (actor_storage.name,
                                                 actor_storage.msg_uuid)
            except AttributeError:
                caller = calling_path

            # Figure out our arguments.
            async_set = "async" in kwargs
            async = kwargs.pop("async", False)
            on_same_greenlet = (self.greenlet == gevent.getcurrent())

            if on_same_greenlet and not async:
                # Bypass the queue if we're already on the same greenlet, or we
                # would deadlock by waiting for ourselves.
                return fn(self, *args, **kwargs)

            # async must be specified, unless on the same actor.
            assert async_set, "All cross-actor event calls must specify async arg."

            if (not on_same_greenlet and
                    not async and
                    _log.isEnabledFor(logging.DEBUG)):
                _log.debug("BLOCKING CALL: %s", calling_path)

            # OK, so build the message and put it on the queue.
            partial = functools.partial(fn, self, *args, **kwargs)
            result = TrackedAsyncResult(method_name)
            msg = Message(partial, [result], caller, self.name,
                          needs_own_batch=needs_own_batch)
            result.set_msg(msg)

            _log.debug("Message %s sent by %s to %s, queue length %d",
                       msg, caller, self.name, self._event_queue.qsize())
            self._event_queue.put(msg, block=False)
            if async:
                return result
            else:
                return result.get()
        queue_fn.func = fn
        return queue_fn
    return decorator
