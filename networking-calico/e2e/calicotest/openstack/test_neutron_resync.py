# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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

import logging
import time

from calicotest.common import datamodel_v3
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import TopologyBasic


_log = logging.getLogger(__name__)


class NeutronResync(TopologyBasic):
    """
    Tests Neutron resynchronization behaviour.
    """

    # These logs come from the test case which creates a corrupt
    # WorkloadEndpoint.
    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS + [
        "Watch error received from Upstream",
    ]

    def setUp(self):
        super(NeutronResync, self).setUp()
        # Baseline etcd against Neutron's view before each test.
        # Earlier test classes in the same CI run can leave orphan
        # NetworkPolicy / WorkloadEndpoint entries in etcd that don't
        # correspond to anything in Neutron; if we picked one of those
        # as the key to delete, the resync triggered later in the test
        # would delete it (as Neutron-extra) rather than recreate it
        # (as Neutron-missing), and the read-back assertion would
        # fail.  No-op on networking-calico versions where the
        # in-server periodic resync still runs.
        self._trigger_resync_if_available(self._datamodel_region_arg())

    def _trigger_resync_if_available(self, region_arg):
        """Run calico-resync on the control node for ``region_arg`` if the
        binary is installed.  Return True if it ran.

        networking-calico >= 3.33.0~rc0.post524 removes the periodic
        resync that used to live inside neutron-server, in favour of an
        explicit one-shot ``calico-resync`` CLI.  The install scripts
        only install the CLI on hosts whose networking-calico is new
        enough to ship it, so the binary's presence on the controller
        is a reliable proxy for "we need to trigger resync explicitly";
        on older versions this method is a no-op and returns False, and
        _read_after_resync waits for the legacy periodic resync instead.
        """
        if region_arg is None:
            node = LAYOUT.control_node
        else:
            node = LAYOUT.control_node_by_region[region_arg]
        if node.execute("test -x /usr/bin/calico-resync").return_code != 0:
            _log.info(
                "calico-resync not installed on %s; relying on legacy "
                "in-server periodic resync.",
                node.fqdn,
            )
            return False
        # Read neutron.conf (so calico-resync sees the same DB/keystone
        # config as neutron-server) and layer the small log-redirect
        # snippet on top so log output doesn't pollute stdout.  The
        # log-redirect config sends oslo.log output to a file on the
        # control node; truncate it before the run and cat it after so
        # we only see output from this specific invocation.
        log_file = "/var/log/calico/calico-resync.log"
        node.execute("sudo truncate -s 0 %s 2>/dev/null || true" % log_file)
        result = node.execute(
            "sudo /usr/bin/calico-resync "
            "--config-file /etc/neutron/neutron.conf "
            "--config-file /etc/calico/calico-resync-log.conf"
        )
        node.execute("sudo cat %s || true" % log_file)
        self.assertEqual(
            result.return_code,
            0,
            "calico-resync failed on %s" % node.fqdn,
        )
        return True

    def _read_after_resync(self, kind, name, region_arg, resynced):
        """Read back a resource that a resync should have restored or fixed.

        calico-resync only exits once the resync is complete, so if we ran it
        (resynced is True), the resource must already be right: read it once, and
        let any error fail the test.  Otherwise, wait up to 70s for the legacy
        in-server periodic resync, and return None if the resource is still missing
        or unreadable after that.
        """
        if resynced:
            return datamodel_v3.get(kind, name, region=region_arg)
        new_spec = None
        time_elapsed = 0
        while new_spec is None and time_elapsed < 70:
            time.sleep(5)
            time_elapsed += 5
            try:
                new_spec = datamodel_v3.get(kind, name, region=region_arg)
            except Exception:
                _log.exception("Trying to read %s %s", kind, name)
        return new_spec

    def test_blow_away_policy_key(self):
        """
        Neutron returns security policy keys that are destroyed in etcd.
        """
        region_arg = self._datamodel_region_arg()

        # Find the key for a policy in etcd.
        _log.info("Searching for policy in etcd")
        policies = datamodel_v3.get_all("NetworkPolicy", region=region_arg)
        if not policies:
            raise RuntimeError("No policies found in etcd!")

        # Unpack the first returned policy tuple.
        name, spec, mod_revision = policies[0]

        # Delete that policy.
        deleted = datamodel_v3.delete("NetworkPolicy", name, region=region_arg)
        _log.info("NetworkPolicy %s deleted = %s", name, deleted)
        self.assertTrue(deleted)

        # Trigger an explicit resync.  No-op on networking-calico
        # versions where the in-server periodic resync is still active.
        resynced = self._trigger_resync_if_available(region_arg)

        # Read back the policy, which the resync should have recreated.
        new_spec = self._read_after_resync("NetworkPolicy", name, region_arg, resynced)

        # Check that the policy spec now is the same as before.
        self.assertEqual(new_spec, spec)

    def test_neutron_fixes_broken_keys(self):
        """
        Neutron fixes keys with invalid data in them.
        """
        region_arg = self._datamodel_region_arg()

        # Find the key for an endpoint in etcd.
        _log.info("Searching for endpoint in etcd")
        endpoints = datamodel_v3.get_all("WorkloadEndpoint", region=region_arg)
        if not endpoints:
            raise RuntimeError("No endpoints found in etcd!")

        # Unpack the first returned endpoint tuple.
        name, spec, mod_revision = endpoints[0]
        vm_id = spec["workload"]

        # Delete that endpoint.
        deleted = datamodel_v3.delete("WorkloadEndpoint", name, region=region_arg)
        _log.info("WorkloadEndpoint %s deleted = %s", name, deleted)
        self.assertTrue(deleted)

        # Trigger an explicit resync.  No-op on networking-calico
        # versions where the in-server periodic resync is still active.
        resynced = self._trigger_resync_if_available(region_arg)

        # Read back the endpoint, which the resync should have recreated.
        new_spec = self._read_after_resync(
            "WorkloadEndpoint", name, region_arg, resynced
        )

        # The key is back, now screw with it.
        datamodel_v3.put(
            "WorkloadEndpoint", name, new_spec, corrupt=True, region=region_arg
        )

        # Felix should now remove routing data for the endpoint. Confirm it.
        # First, locate the VM object that matches the key we just messed with.
        _log.info("Checking VM is unreachable.")
        unreachable_vm = None
        for vm in self.vms:
            if vm.vm.id == vm_id:
                unreachable_vm = vm
                break
        else:
            raise RuntimeError("Could not locate damaged VM")

        reachable = (v for v in self.vms if v is not unreachable_vm)
        unreachable = (v for v in self.vms if v is unreachable_vm)
        self.check_mutual_connectivity(reachable, unreachable)

        # Trigger an explicit resync so the corrupted key is rewritten
        # from neutron's view of the data model.  No-op on older
        # networking-calico (legacy periodic resync still applies).
        resynced = self._trigger_resync_if_available(region_arg)

        # Read back the endpoint, which the resync should have fixed.
        _log.info("Check that the key has been fixed up.")
        new_spec = self._read_after_resync(
            "WorkloadEndpoint", name, region_arg, resynced
        )

        # Check that the endpoint spec now is the same as before.
        self.assertEqual(new_spec, spec)

        # All VMs should now be reachable.
        _log.info("Checking VM is reachable again.")
        self.check_mutual_connectivity(self.vms, [])
