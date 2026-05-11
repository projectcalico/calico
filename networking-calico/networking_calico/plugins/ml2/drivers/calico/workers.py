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

Each subclass corresponds to one OS process forked by neutron-server, with one
specific job.  The subclass itself is essentially a marker: the actual work is
driven by the mech driver's ``post_fork_initialize`` callback, which dispatches
based on the trigger's class.
"""

import threading

from neutron.common import config
from neutron_lib import worker


class CalicoStartupResyncWorker(worker.BaseWorker):
    """Worker that runs the one-shot Neutron-DB-to-etcd resync.

    Spawned (in its own OS process) by neutron-server when ``[calico] startup_resync``
    is ``always`` (the default).  The mech driver's ``post_fork_initialize`` callback
    recognises this trigger class, builds the per-process state (DB connection, syncers,
    Keystone client) and invokes the same ``Scope().run()`` entry point that the
    ``calico-resync`` CLI uses.  The worker process then idles for the lifetime of
    neutron-server.

    Failures are logged loudly but not retried; an operator can drive a retry via
    ``calico-resync --all`` or by restarting neutron-server.

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

    def start(self, name="calico-startup-resync", desc=None):
        super(CalicoStartupResyncWorker, self).start(name, desc)
        self._stop_event = threading.Event()

    def wait(self):
        # Block until stop() is called.  The mech driver's post-fork callback
        # ran the actual work; this just keeps the process alive so the
        # neutron-server supervisor doesn't respawn us.
        self._stop_event.wait()

    def stop(self):
        # threading.Event.set() is idempotent.
        self._stop_event.set()

    def reset(self):
        config.reset_service()
