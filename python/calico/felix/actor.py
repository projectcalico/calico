# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
to methods decorated by the @actor_message decorator.

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
from calico.monotonic import monotonic_time, cpu_time
import gevent
import gevent.local
import logging
import os
import random
import sys
import traceback
import weakref

from gevent.event import AsyncResult
from calico.felix import futils
from calico.felix.futils import StatCounter

_log = logging.getLogger(__name__)

# Minimum gevent scheduling delay.  A delay of 0 should mean "yield" but
# gevent has a known issue that a greenlet that sleeps for 0 may be rescheduled
# immediately.  Any small positive value is enough to truly yield.
MIN_DELAY = 0.000001

ResultOrExc = collections.namedtuple("ResultOrExc", ("result", "exception"))

# Local storage to allow diagnostics.
actor_storage = gevent.local.local()

# Global diagnostic counters.
_stats = StatCounter("Actor framework counters")


_time_buckets = collections.defaultdict(lambda: 0)
_time_bucket_counts = collections.defaultdict(lambda: 0)
_last_switch_out_time = cpu_time()


class TimedGreenlet(gevent.Greenlet):
    def __init__(self, run=None, *args, **kwargs):
        time_bucket = kwargs.pop("time_bucket", None)
        if time_bucket is None:
            if run is not None:
                try:
                    # Bare func.
                    time_bucket = run.func_name
                except AttributeError:
                    try:
                        # Method.
                        time_bucket = run.im_func.func_name
                    except AttributeError:
                        pass
            else:
                time_bucket = self.__class__.__name__

        super(TimedGreenlet, self).__init__(run, *args, **kwargs)
        self._switch_in_time = None
        self.total_time = 0
        self.time_bucket = time_bucket

    def switch(self, *args):
        self._switch_in_time = cpu_time()
        hub_time = self._switch_in_time - _last_switch_out_time
        _time_bucket_counts["**Hub**"] += 1
        _time_buckets["**Hub**"] += hub_time
        super(TimedGreenlet, self).switch(*args)

    def switch_out(self):
        switch_out_time = cpu_time()
        global _last_switch_out_time
        _last_switch_out_time = switch_out_time
        delta = (switch_out_time - self._switch_in_time)
        self.total_time += delta
        _time_bucket_counts[self.time_bucket] += 1
        _time_buckets[self.time_bucket] += delta


class Actor(object):
    """
    Class that contains a queue and a greenlet serving that queue.
    """

    max_ops_before_yield = 1000
    """Number of calls to self._maybe_yield before it yields"""

    batch_delay = 0.01
    """
    Minimum delay between schedules of this Actor.  Larger values encourage
    more batching of messages and reduce starvation (but introduce more
    latency when we're under load).
    """

    def __init__(self, qualifier=None, time_bucket=None):
        self._event_queue = collections.deque()

        # Set to True when the main loop is actively processing the input
        # queue or has been scheduled to do so.  Set to False when the loop
        # runs out of work and switches to the Hub to wait for more.
        self._scheduled = True
        # (Monotonic time) timestamp of last schedule.
        self._last_scheduled = None
        # Cache the gevent Hub and main loop.
        self._gevent_hub = gevent.get_hub()
        self._gevent_loop = self._gevent_hub.loop

        self.greenlet = TimedGreenlet(
            self._loop,
            time_bucket=time_bucket or self.__class__.__name__
        )
        self._op_count = 0
        self._current_msg = None
        self.started = False

        # Message being processed; purely for logging.
        self.msg_id = None

        # Logging parameters
        self.qualifier = qualifier
        if qualifier:
            self.name = "%s(%s)" % (self.__class__.__name__, qualifier)
        else:
            self.name = self.__class__.__name__
        # Can't use str(self) yet, it might not be ready until subclass
        # constructed.
        _log.info("%s created.", self.name)

    def maybe_schedule(self, caller):
        """
        Schedule this Actor to run iff it is not already running/scheduled.

        :param str caller: A (debug) tag to pass to the greenlet to identify
               the caller
        """
        # This method uses very low-level gevent APIs for performance, it is
        # partially cribbed from gevent's Waiter class, which is a simple
        # application of the low-level APIs.

        _log.debug("Checking whether we need to schedule %s", self)
        # We use the lack of yield points in this code to ensure that no-one
        # changes self._scheduled between the next two lines.  Do not add
        # logging between the test and set of self._scheduled.
        if not self._scheduled:
            self._scheduled = True
            # Calculate the scheduling delay.  If this Actor hasn't been
            # scheduled for a long time, we'll schedule it straight away,
            # otherwise we back off to the batch_delay to encourage work to be
            # batched up when we're under load.
            now = monotonic_time()
            if self._last_scheduled is not None:
                time_since_last_schedule = now - self._last_scheduled
                delay = max(self.batch_delay - time_since_last_schedule,
                            MIN_DELAY)
            else:
                delay = MIN_DELAY
            # We can't switch directly to the Actor's greenlet because that
            # prevents gevent from doing its scheduling.  Instead, we ask the
            # gevent event loop to switch to the greenlet.
            t = self._gevent_loop.timer(delay)
            t.start(self._switch, caller)
            self._last_scheduled = now
            _log.debug("Scheduled %s", self)

    def _switch(self, value):
        """
        Switch to this Actor's greenlet, handling errors via the Hub's
        handle_error method.

        This should only be called from the gevent Hub.
        """
        # This method uses very low-level gevent APIs for performance, it is
        # partially cribbed from gevent's Waiter class, which is a simple
        # application of the low-level APIs.

        # WARNING: this method is called from the gevent Hub, it cannot use
        # logging because logging can do IO, which is illegal from the Hub.
        switch = self.greenlet.switch
        try:
            self.greenlet.switch(value)
        except:
            self._gevent_hub.handle_error(switch, *sys.exc_info())

    def start(self):
        assert not self.greenlet, "Already running"
        _log.info("Starting %s", self)
        self.started = True
        self.greenlet.start()
        return self

    def _loop(self):
        """
        Main greenlet loop, repeatedly runs _step().  Doesn't return normally.
        """
        actor_storage.class_name = self.__class__.__name__
        actor_storage.name = self.name
        actor_storage.msg_id = None
        _log.info("Main loop for actor %s started.", self)
        try:
            self._on_actor_started()
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
        hub = gevent.get_hub()
        while not self._event_queue:
            # We've run out of work to process, note that fact and then switch
            # to the Hub to allow something else to run.  actor_message will
            # wake us up when there's more work to do.
            self._scheduled = False
            caller = hub.switch()
            # Before actor_message switches to us, it should set _scheduled
            # back to True.
            assert self._scheduled, ("Switched to %s from %s but _scheduled "
                                     "set to False." % (self, caller))
        msg = self._event_queue.popleft()

        batch = [msg]
        batches = []

        if not msg.needs_own_batch:
            # Try to pull some more work off the queue to combine into a
            # batch.
            while self._event_queue:
                # We're the only ones getting from the queue so this should
                # never fail.
                msg = self._event_queue.popleft()
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
                           len(self._event_queue))
                self._current_msg = msg
                actor_storage.msg_id = msg.msg_id
                actor_storage.msg_name = msg.name
                try:
                    # Actually execute the per-message method and record its
                    # result.
                    result = msg.method()
                except BaseException as e:
                    _log.exception("Exception processing %s", msg)
                    results.append(ResultOrExc(None, e))
                    _stats.increment("Messages executed with exception")
                else:
                    results.append(ResultOrExc(result, None))
                    _stats.increment("Messages executed OK")
                finally:
                    self._current_msg = None
                    actor_storage.msg_id = None
                    actor_storage.msg_name = None
            try:
                # Give subclass a chance to post-process the batch.
                _log.debug("Finishing message batch of length %s", len(batch))
                actor_storage.msg_name = "<finish batch>"
                self._finish_msg_batch(batch, results)
            except SplitBatchAndRetry:
                # The subclass couldn't process the batch as is (probably
                # because a failure occurred and it couldn't figure out which
                # message caused the problem).  Split the batch into two and
                # re-run it.
                _log.warn("Splitting batch to retry.")
                self.__split_batch(batch, batches)
                num_splits += 1  # For diags.
                _stats.increment("Split batches")
                continue
            except BaseException as e:
                # Most-likely a bug.  Report failure to all callers.
                _log.exception("_finish_msg_batch failed.")
                results = [(None, e)] * len(results)
                _stats.increment("_finish_msg_batch() exception")
            else:
                _log.debug("Finished message batch successfully")
            finally:
                actor_storage.msg_name = None

            # Batch complete and finalized, set all the results.
            assert len(batch) == len(results)
            for msg, (result, exc) in zip(batch, results):
                for future in msg.results:
                    if exc is not None:
                        future.set_exception(exc)
                    else:
                        future.set(result)
                    _stats.increment("Messages completed")

            _stats.increment("Batches processed")
        if num_splits > 0:
            _log.warn("Split batches complete. Number of splits: %s",
                      num_splits)

    def _on_actor_started(self):
        """Called on the actor's thread after the actor is started.

        Called before any messages are processed.

        Intended to be overridden, this implementation does nothing.
        """
        pass

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
            gevent.sleep(MIN_DELAY)
            self._op_count = 0

    def __str__(self):
        return self.__class__.__name__ + "<%s,queue_len=%s,live=%s,msg=%s,time=%.3fs>" % (
            self.qualifier,
            len(self._event_queue),
            bool(self.greenlet),
            self._current_msg,
            getattr(self.greenlet, "total_time", -1.0),
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


# Start with a random offset to make the log easier to grep.
next_message_id = random.randint(0, sys.maxint)


class Message(object):
    """
    Message passed to an actor.
    """
    __slots__ = ("msg_id", "method", "results", "caller", "name",
                 "needs_own_batch", "recipient")

    def __init__(self, msg_id,  method, results, caller_path, recipient,
                 needs_own_batch):
        self.msg_id = msg_id
        self.method = method
        self.results = results
        self.caller = caller_path
        self.name = method.func.__name__
        self.needs_own_batch = needs_own_batch
        self.recipient = recipient
        _stats.increment("Messages created")

    def __str__(self):
        data = ("%s (%s)" % (self.msg_id, self.name))
        return data


def actor_message(needs_own_batch=False):
    """
    Decorator: turns a method into an Actor message.

    Calls to the wrapped method will be queued via the Actor's message queue.
    The caller to a wrapped method must specify the async=True/False
    argument to specify whether they want their own thread to block
    waiting for the result.

    If async=True is passed, the wrapped method returns an AsyncResult.
    Otherwise, it blocks and returns the result (or raises the exception)
    as-is.

    Using async=False to block the current thread can be very convenient but
    it can also deadlock if there is a cycle of blocking calls.  Use with
    caution.

    :param bool needs_own_batch: True if this message should be processed
        in its own batch.
    """
    def decorator(fn):
        method_name = fn.__name__

        @functools.wraps(fn)
        def queue_fn(self, *args, **kwargs):
            # Calculating the calling information is expensive, so only do it
            # if debug is enabled.
            caller = "<disabled>"
            caller_name = "<disabled>"
            calling_path = "<disabled>"

            if _log.isEnabledFor(logging.DEBUG):
                # Get call information for logging purposes.
                calling_file, line_no, func, _ = traceback.extract_stack()[-2]
                calling_file = os.path.basename(calling_file)
                calling_path = "%s:%s:%s" % (calling_file, line_no, func)
                try:
                    caller_name = "%s.%s" % (actor_storage.class_name,
                                             actor_storage.msg_name)
                    caller = "%s (processing %s)" % (actor_storage.name,
                                                     actor_storage.msg_id)
                except AttributeError:
                    caller_name = calling_path
                    caller = calling_path

            # Figure out our arguments.
            async_set = "async" in kwargs
            async = kwargs.pop("async", False)
            on_same_greenlet = (self.greenlet == gevent.getcurrent())
            if on_same_greenlet and not async:
                # Bypass the queue if we're already on the same greenlet, or we
                # would deadlock by waiting for ourselves.
                return fn(self, *args, **kwargs)
            else:
                # Only log a stat if we're not simulating a normal method call.
                # WARNING: only use stable values in the stat name.
                # For example, Actor.name can be different for every actor,
                # resulting in leak if we use that.
                _stats.increment(
                    "%s message %s --[%s]-> %s" %
                    ("ASYNC" if async else "BLOCKING",
                     caller_name,
                     method_name,
                     self.__class__.__name__)
                )

            # async must be specified, unless on the same actor.
            assert async_set, "Cross-actor event calls must specify async arg."

            # Allocate a message ID.  We rely on there being no yield point
            # here for thread safety.
            global next_message_id
            msg_id = "M%016x" % next_message_id
            if next_message_id == sys.maxint:
                next_message_id = 0
            else:
                next_message_id += 1

            if not on_same_greenlet and not async:
                _stats.increment("Blocking calls started")
                _log.debug("BLOCKING CALL: [%s] %s -> %s", msg_id,
                           calling_path, method_name)

            # OK, so build the message and put it on the queue.
            partial = functools.partial(fn, self, *args, **kwargs)
            result = TrackedAsyncResult((calling_path, caller,
                                         self.name, method_name))
            msg = Message(msg_id, partial, [result], caller, self.name,
                          needs_own_batch=needs_own_batch)

            _log.debug("Message %s sent by %s to %s, queue length %d",
                       msg, caller, self.name, len(self._event_queue))
            self._event_queue.append(msg)
            self.maybe_schedule(caller)
            if async:
                return result
            else:
                blocking_result = None
                try:
                    blocking_result = result.get()
                except BaseException as e:
                    blocking_result = e
                    raise
                finally:
                    _stats.increment("Blocking calls completed")
                    _log.debug("BLOCKING CALL COMPLETE: [%s] %s -> %s = %r",
                               msg_id, calling_path, method_name,
                               blocking_result)
                return blocking_result
        queue_fn.func = fn
        return queue_fn
    return decorator


# Each time we create a TrackedAsyncResult, me make a weak reference to it
# so that we can get a callback (_on_ref_reaped()) when the TrackedAsyncResult
# is GCed.  This is roughly equivalent to adding a __del__ method to the
# TrackedAsyncResult but it doesn't interfere with the GC.
#
# In order for the callback to get called, we have to keep the weak reference
# alive until after the TrackedAsyncResult itself is GCed.  To do that, we
# stash a reference to the weak ref in this dict and then clean it up in
# _on_ref_reaped().
_tracked_refs_by_idx = {}
_ref_idx = 0


def dump_actor_diags(log):
    log.info("Current ref index: %s", _ref_idx)
    log.info("Number of tracked messages outstanding: %s",
             len(_tracked_refs_by_idx))
    for bucket, time in _time_buckets.items():
        count = _time_bucket_counts[bucket]
        per_instance = time / count
        log.info("Time spent in % 28s: \t%.3fs %.3fms (%s)",
                 bucket, time, per_instance*1000, count)
futils.register_diags("Actor framework", dump_actor_diags)


class ExceptionTrackingWeakRef(weakref.ref):
    """
    Specialised weak reference with a slot to hold an exception
    that was leaked.
    """

    # Note: superclass implements __new__ so we have to mimic its args
    # and have the callback passed in.
    def __init__(self, obj, callback):
        super(ExceptionTrackingWeakRef, self).__init__(obj, callback)
        self.exception = None
        self.tag = None

        # Callback won't get triggered if we die before the object we reference
        # so stash a reference to this object, which we clean up when the
        # TrackedAsyncResult is GCed.
        global _ref_idx
        self.idx = _ref_idx
        _ref_idx += 1
        _tracked_refs_by_idx[self.idx] = self

    def __str__(self):
        return (self.__class__.__name__ + "<%s/%s,exc=%s>" %
                (self.tag, self.idx, self.exception))


def _on_ref_reaped(ref):
    """
    Called when a TrackedAsyncResult gets GCed.

    Looks for leaked exceptions.

    :param ExceptionTrackingWeakRef ref: The ref that may contain a leaked
        exception.
    """
    # Future maintainers: This function *must not* do any IO of any kind, or
    # generally do anything that would cause gevent to yield the flow of
    # control. See issue #587 for more details.
    assert isinstance(ref, ExceptionTrackingWeakRef)
    del _tracked_refs_by_idx[ref.idx]
    if ref.exception:
        try:
            msg = ("TrackedAsyncResult %s was leaked with "
                   "exception %r.  Dying." % (ref.tag, ref.exception))
            _print_to_stderr(msg)
        finally:
            # Called from the GC so we can't raise an exception, just die.
            _exit(1)


class TrackedAsyncResult(AsyncResult):
    """
    An AsyncResult that tracks if any exceptions are leaked.
    """
    def __init__(self, tag):
        super(TrackedAsyncResult, self).__init__()
        # Avoid keeping a reference to the weak ref directly; look it up
        # when needed.  Also, be careful not to attach any debugging
        # information to the ref that could produce a reference cycle.  The
        # tag should be something simple like a string or tuple.
        tr = ExceptionTrackingWeakRef(self, _on_ref_reaped)
        tr.tag = tag
        self.__ref_idx = tr.idx

    @property
    def __ref(self):
        return _tracked_refs_by_idx[self.__ref_idx]

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


# Factored out for UTs to stub.
def _print_to_stderr(msg):
    print >> sys.stderr, msg


def _exit(rc):
    """
    Immediately terminates this process with the given return code.

    This function is mainly here to be mocked out in UTs.
    """
    os._exit(rc)  # pragma nocover
