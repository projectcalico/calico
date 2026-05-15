from neutron_lib import worker

from neutron.common import config


class WorkloadEndPointSyncer(worker.BaseWorker):

    def start(self, name="wep-syncer", desc=None):
        """Start service."""
        super(WorkloadEndPointSyncer, self).start(name, desc)

    def stop(self):
        """Stop service."""
        super(WorkloadEndPointSyncer, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(WorkloadEndPointSyncer, self).wait()

    def reset(self):
        config.reset_service()
