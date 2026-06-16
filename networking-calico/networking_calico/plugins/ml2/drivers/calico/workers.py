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

"""Neutron BaseWorker subclasses that the Calico mech driver returns from
``get_workers()``.

Each subclass corresponds to one OS process forked by neutron-server, with one specific
job.  The subclass itself is essentially a marker: the actual work is driven by the mech
driver's ``post_fork_initialize`` callback, which dispatches based on the trigger's
class.
"""

import threading

import eventlet.patcher
from neutron.common import config
from neutron_lib import worker
from oslo_log import log


LOG = log.getLogger(__name__)


class CalicoStartupResyncWorker(worker.BaseWorker):
    """Worker that runs the one-shot Neutron-DB-to-etcd resync.

    Spawned (in its own OS process) by neutron-server when ``[calico] startup_resync``
    is ``always`` (the default).  The mech driver's ``post_fork_initialize`` callback
    recognises this trigger class, builds the per-process state (DB connection, syncers,
    Keystone client) and invokes the same ``Scope().run()`` entry point that the
    ``calico-resync`` CLI uses.  The worker process then idles for the lifetime of
    neutron-server.

    Failures are logged loudly but not retried; an operator can drive a retry by running
    ``calico-resync`` with no scope flags (which means resync everything) or by
    restarting neutron-server.

    The "do the work, then idle in wait()" pattern is intentional.  Neutron's worker
    supervisor expects long-running services and may respawn a worker that exits
    cleanly; blocking on a stop event in ``wait()`` keeps the process alive without
    doing anything until shutdown.

    We use ``threading.Event`` rather than ``eventlet.event.Event`` so the primitive
    remains correct after the eventlet removal transition.  Under eventlet,
    ``neutron-server``'s process-wide ``monkey_patch`` makes ``threading.Event``
    cooperative; without eventlet it's a real thread primitive.  Either way, ``wait()``
    blocks until ``set()`` is called.
    """

    def __init__(self, *args, **kwargs):
        super(CalicoStartupResyncWorker, self).__init__(*args, **kwargs)
        # Create the stop event here, not in start(), because oslo_service can call
        # wait() / stop() on the worker independently of start() - e.g. during
        # fork-and-supervise teardown if start() hasn't run in this process yet.  Having
        # _stop_event exist from __init__ makes wait() and stop() safe to call in any
        # order.
        self._stop_event = threading.Event()
        # Record whether eventlet has hijacked the underlying thread primitives.
        # threading.Event remains correct either way (it picks up whichever lock _thread
        # provides), but logging this once gives us a tripwire for when neutron-server's
        # eventlet monkey-patching changes - notably the planned eventlet removal, after
        # which this should flip from True to False without any code change needed here.
        LOG.info(
            "CalicoStartupResyncWorker: eventlet thread monkey-patch = %s",
            eventlet.patcher.is_monkey_patched("thread"),
        )

    def start(self, name="calico-startup-resync", desc=None):
        super(CalicoStartupResyncWorker, self).start(name, desc)

    def wait(self):
        # Block until stop() is called.  The mech driver's post-fork callback ran the
        # actual work; this just keeps the process alive so the neutron-server
        # supervisor doesn't respawn us.
        self._stop_event.wait()

    def stop(self):
        # threading.Event.set() is idempotent.
        self._stop_event.set()

    def reset(self):
        config.reset_service()


class CalicoManagerWorker(worker.BaseWorker):
    """Service for doing election and compaction.

    The super class will trigger the post_fork_initialize in the mech driver.
    """

    def start(self, name="calico-manager", desc=None):
        """Start service."""
        super(CalicoManagerWorker, self).start(name, desc)

    def stop(self):
        """Stop service."""
        super(CalicoManagerWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(CalicoManagerWorker, self).wait()

    def reset(self):
        config.reset_service()


class CalicoAgentStatusWatcherWorker(worker.BaseWorker):
    """Service for watching and updating calico-felix agent health.

    The super class will trigger the post_fork_initialize in the mech driver.
    """

    def start(self, name="calico-agent-status-watcher", desc=None):
        """Start service."""
        super(CalicoAgentStatusWatcherWorker, self).start(name, desc)

    def stop(self):
        """Stop service."""
        super(CalicoAgentStatusWatcherWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(CalicoAgentStatusWatcherWorker, self).wait()

    def reset(self):
        config.reset_service()


class CalicoEndpointStatusWatcherWorker(worker.BaseWorker):
    """Service for watching and updating endpoint status.

    The super class will trigger the post_fork_initialize in the mech driver.
    """

    def start(self, name="calico-endpoint-status-watcher", desc=None):
        """Start service."""
        super(CalicoEndpointStatusWatcherWorker, self).start(name, desc)

    def stop(self):
        """Stop service."""
        super(CalicoEndpointStatusWatcherWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(CalicoEndpointStatusWatcherWorker, self).wait()

    def reset(self):
        config.reset_service()
