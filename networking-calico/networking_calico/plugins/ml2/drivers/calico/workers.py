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

from neutron.common import config
from neutron_lib import worker
from oslo_log import log


LOG = log.getLogger(__name__)


class CalicoResourceSyncerWorker(worker.BaseWorker):
    """Service for the periodic resync from the Neutron DB to etcd.

    The super class will trigger the post_fork_initialize in the mech driver.
    """

    def start(self, name="calico-resource-syncer", desc=None):
        """Start service."""
        super(CalicoResourceSyncerWorker, self).start(name, desc)

    def stop(self):
        """Stop service."""
        super(CalicoResourceSyncerWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(CalicoResourceSyncerWorker, self).wait()

    def reset(self):
        config.reset_service()


class CalicoManagerWorker(worker.BaseWorker):
    """Service for doing election and compaction.

    The super class will trigger the post_fork_initialize in the mech driver.

    Holds a back-reference to the mech driver so stop() can ask the elector
    to step down cleanly.  Without that, neutron-server's SIGTERM would just
    kill the elector greenlet, the ``finally: _attempt_step_down()`` block
    would not run, and the election key would linger in etcd until its lease
    expired -- adding ttl seconds of delay before any node could win the
    next election.
    """

    def __init__(self, driver=None, *args, **kwargs):
        super(CalicoManagerWorker, self).__init__(*args, **kwargs)
        self._driver = driver

    def start(self, name="calico-manager", desc=None):
        """Start service."""
        super(CalicoManagerWorker, self).start(name, desc)

    def stop(self):
        """Stop service.

        Step down from mastership before chaining to the base ``stop()``.
        The elector's stop() blocks until its greenlet has exited, which is
        what runs the ``finally: _attempt_step_down()`` that deletes the
        election key in etcd.  Guarded against the case where stop() fires
        before post_fork_initialize has populated ``driver.elector``.
        """
        elector = getattr(self._driver, "elector", None) if self._driver else None
        if elector is not None:
            try:
                elector.stop()
            except Exception:
                # Best-effort -- we are already on the shutdown path, and
                # the key will expire with its lease either way.
                LOG.exception("Error stopping elector during worker shutdown")
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
