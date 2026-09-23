# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Diagnostics for the SQLAlchemy-fairy GC-in-eventlet-hub race.

The race
--------
We have sometimes been seeing this exception in journalctl.txt / neutron-server.log:

Exception ignored in: <function _ConnectionRecord.checkout.<locals>.<lambda>
    at 0x72810792e290>
Traceback (most recent call last):
  File ".../site-packages/sqlalchemy/pool/base.py", line 509, in <lambda>
    and _finalize_fairy(
  File ".../site-packages/sqlalchemy/pool/base.py", line 800, in _finalize_fairy
    connection_record.checkin()
  File ".../site-packages/sqlalchemy/pool/base.py", line 544, in checkin
    pool.dispatch.checkin(connection, self)
  File ".../site-packages/sqlalchemy/event/attr.py", line 346, in __call__
    fn(*args, **kw)
  File ".../site-packages/oslo_db/sqlalchemy/engines.py", line 52, in _thread_yield
    time.sleep(0)
  File ".../site-packages/eventlet/greenthread.py", line 37, in sleep
    hub.switch()
  File ".../site-packages/eventlet/hubs/hub.py", line 310, in switch
    return self.greenlet.switch()
TimeoutError: timed out

This occurs when a Neutron DB context uses a session (for some reason) and then leaks
it, and GC kicks in on eventlet's "hub" greenlet.  An sqlalchemy connection fairy that
is GC'd while the eventlet hub greenlet is the current greenlet triggers oslo.db's
``_thread_yield`` checkin listener to call ``time.sleep(0)`` -> ``hub.switch()``, which
deadlocks because the hub cannot switch to itself.  The ``TimeoutError`` that eventually
fires is silently swallowed by Python's "Exception ignored in" finalizer-exception
mechanism, but each occurrence wedges the hub for ~10s and leaves the connection
record's pool state indeterminate.

I _think_ #13015 fixes the primary root cause of this, by adding a transaction wrapper
around raw `context.session.query` calls.  The wrapper properly closes the session after
those calls, instead of leaking it to GC.  However, in case there are any remaining
cases, e.g. because a Neutron-framework path outside our control drops a session
unclosed, or because a future change reintroduces a code path that bypasses the
``using`` pattern -- we want a log line that points at the leaking code path rather than
just the in-hub finalizer stack that the existing "Exception ignored in" trace gives us.

Low-level detail
----------------
An SQLAlchemy connection ``_ConnectionFairy`` is the user-facing wrapper returned by
``Pool.connect()`` (or, transitively, by ``Session.connection()`` when a session
executes its first SQL).  Every fairy has a weakref finalizer (the ``<lambda>``
registered inside ``_ConnectionRecord.checkout``) that, if the fairy is GC'd without
explicit checkin, calls ``connection_record.checkin()`` -- which dispatches the
SQLAlchemy ``checkin`` event.  oslo.db registers ``_thread_yield`` on that event, which
calls ``time.sleep(0)``.

Under eventlet, ``time.sleep(0)`` is monkey-patched to ``hub.switch()``.  If we're
already executing in the hub greenlet at the moment of GC (possible whenever GC fires
during the hub's own bookkeeping), ``hub.switch()`` from the hub to itself fails to find
a target and times out as ``TimeoutError``.  Python's "Exception ignored in" mechanism
swallows the error, but the hub has been wedged for ~10s and the connection record's
state is indeterminate.

In current code (after PR 13015), our DB access falls into two patterns: raw
``context.session.query(...)`` calls inside explicit ``db_api.CONTEXT_*.using`` blocks
(which close the session deterministically at block exit via oslo.db's
``_TransactionContext._session`` finally-block calling ``session.close()``); and
``@db_api.retry_if_session_inactive``-decorated plugin API calls (``self.db.get_*``,
etc.) outside any explicit ``using`` block, which rely on SQLAlchemy's own session
lifecycle.  In the deployments we have tested neither pattern leaves a fairy for GC, but
the decorator-only path is the weaker of the two -- the retry wrapper doesn't open its
own ``using`` block, so deterministic close isn't guaranteed there.  This module is the
safety net for cases where it isn't enough -- e.g. if a Neutron-framework path outside
our control drops a session unclosed, or if a decorator-based call path leaks a fairy
under some condition we haven't exercised.  If the race fires again the diagnostic
output identifies which code path checked out the leaking connection, so a targeted fix
can follow.

What this module does
---------------------
Two SQLAlchemy event listeners, installed on ``sqlalchemy.pool.Pool`` (so all engines in
the process inherit them):

1. A ``checkout`` listener that captures a stack trace at the point the connection was
   checked out, stashing it on ``connection_record.info["calico_checkout_stack"]``.
   This is how we attribute a later GC to a specific code path: when the fairy is
   eventually GC'd, the same connection record is used for checkin, and we can read the
   stored stack to see *who* originally asked for this connection.

2. A ``checkin`` listener with ``insert=True`` (so it runs *before* oslo.db's
   ``_thread_yield``) that:

     * Checks whether we're currently running in the eventlet hub greenlet.

     * If yes -- i.e. we're about to hit the deadlock -- logs a WARNING containing both
       the checkout-time stack and the current finalizer stack.

   It does *not* attempt to suppress oslo.db's listener; the ``TimeoutError`` will still
   fire and be silently caught.  This keeps the module purely diagnostic (no behavioural
   change), so it can be left on indefinitely.

Cost
----
Capturing a stack trace per pool checkout is not free.  At rough benchmark depth (~30
frames, plain Neutron handler chain) it adds ~50-100us per checkout.  Under a heavy
scale workload this adds up to a small number of seconds of total overhead -- noticeable
but not crippling.  The module is therefore default-off; enable via:

    [calico]
    fairy_gc_diagnostics = True

in neutron.conf when running workloads where the race is suspected.
"""

import traceback

from oslo_log import log
from sqlalchemy import event
from sqlalchemy.pool import Pool


LOG = log.getLogger(__name__)


# Module-level flag so install() runs at most once per process: subsequent calls are
# no-ops regardless of whether the first call actually registered listeners or bailed
# out early.  The flag means "decision made", not "listeners active" -- without this,
# repeat calls would re-emit the early-return WARNING each time, contradicting the
# docstring's "single WARNING" promise.
_INSTALL_ATTEMPTED = False


def install():
    """Idempotently install the fairy-GC diagnostic listeners.

    Safe to call multiple times (subsequent calls in the same process are no-ops).
    Calling install() in the parent before workers are forked is sufficient: the
    SQLAlchemy event listeners attach to the ``Pool`` class, so each forked worker
    inherits them as part of its post-fork memory image and does not need to
    re-install.

    If eventlet is not importable -- e.g. after the planned eventlet removal in
    neutron-server -- this is a no-op with a single WARNING log line.  The race the
    listeners detect only fires under eventlet, so there is nothing useful to install in
    that case, and we deliberately do not want a per-checkin ImportError-driven log
    storm.
    """
    global _INSTALL_ATTEMPTED
    if _INSTALL_ATTEMPTED:
        return
    # Commit to the decision now so any early return below still counts as
    # "already attempted" and we do not re-log the early-return WARNING on
    # subsequent calls.
    _INSTALL_ATTEMPTED = True

    try:
        import eventlet.greenthread
        import eventlet.hubs
        import eventlet.patcher
    except ImportError:
        LOG.warning(
            "Calico fairy-GC diagnostics: eventlet not importable, not "
            "installing listeners.  The race this module detects only "
            "fires under eventlet."
        )
        return

    if not eventlet.patcher.is_monkey_patched("time"):
        LOG.warning(
            "Calico fairy-GC diagnostics: eventlet is importable but time is not "
            "monkey-patched; not installing listeners.  The race this module detects "
            "requires eventlet monkey-patching."
        )
        return

    @event.listens_for(Pool, "checkout")
    def _calico_track_checkout(dbapi_conn, connection_record, connection_proxy):
        # Capture the call stack at the moment of checkout, so a later finalizer-fired
        # checkin can report where the connection was originally given out.  Format
        # eagerly (rather than storing a ``sys._getframe()`` reference) because the
        # frames need to outlive the current call -- the connection may sit in the pool
        # for a long time before being GC'd, and lazy formatting would race the frames
        # being collected themselves.
        #
        # Bounded at the most-recent 50 frames: a Neutron handler chain is typically
        # ~30 frames, so 50 covers the full path through the driver in normal cases
        # and caps the worst case (e.g. a pathological deep-recursion middleware) so
        # we do not burn unbounded CPU per checkout or stash unbounded strings on
        # long-lived ``connection_record.info`` entries.
        connection_record.info["calico_checkout_stack"] = "".join(
            traceback.format_stack(limit=50)
        )

    @event.listens_for(Pool, "checkin", insert=True)
    def _calico_detect_in_hub_checkin(dbapi_conn, connection_record):
        # ``insert=True`` prepends this listener so it runs before oslo.db's
        # ``_thread_yield``.  If we're in the hub greenlet, ``_thread_yield`` is about
        # to call ``time.sleep(0)`` -> ``hub.switch()`` and deadlock.  Log enough
        # context to identify the originating code path before that happens.
        creating_stack = connection_record.info.pop(
            "calico_checkout_stack", "<not captured>"
        )
        hub = eventlet.hubs.get_hub()
        if eventlet.greenthread.getcurrent() is hub.greenlet:
            LOG.warning(
                "Calico fairy-GC diagnostic: connection checkin firing "
                "in eventlet hub greenlet -- oslo.db's _thread_yield is "
                "about to call time.sleep(0), which will deadlock as "
                "TimeoutError.\n"
                "  Connection was checked out at:\n%s\n"
                "  Current finalizer stack:\n%s",
                creating_stack,
                # Finalizer stack is typically shallower than the checkout-time
                # stack (just the GC / weakref-finalizer path into us), so 30
                # frames is plenty.
                "".join(traceback.format_stack(limit=30)),
            )

    LOG.info("Calico fairy-GC diagnostics installed")
