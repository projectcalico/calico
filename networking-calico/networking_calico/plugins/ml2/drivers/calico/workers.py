from neutron.common import config
from neutron_lib import worker


class CalicoResourceSyncerWorker(worker.BaseWorker):
    """Service for syncing Calico resources to etcd.

    The super class will trigger the post_fork_initialize in the mech driver.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
