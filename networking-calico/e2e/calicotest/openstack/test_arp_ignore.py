# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
import subprocess
import time

from calicotest.common import datamodel_v3
from calicotest.common import osutils
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import TopologyBasic


_log = logging.getLogger(__name__)


class TestARPIgnore(TopologyBasic):
    # Tests reliable connectivity to a VM that is configured to ignore ARP requests from
    # the hypervisor.
    #
    # With such VMs there is still an initial window of unreliable connectivity -
    # between when the VM is first created and 90-120s after that - but this test is
    # concerned with verifying the ongoing connectivity _after_ that, i.e. from 90-120s
    # onwards.
    #
    # To verify that, the approach of this test is as follows.
    #
    # - Try to ping the VM every 5 seconds, and record whether each ping succeeds.
    #
    # - Keep doing this for up to 4 minutes.
    #
    # - If we get a run of successful pings for a whole 60s, and the first of those was
    #   60s or more after the VM was created, the test passes.
    #
    # - If we get to 4 minutes, and have not had a run of successful pings like that,
    #   the test fails.
    #
    # The initial window arises because Felix programs a permanent ARP entry for the VM
    # when it first sees the VM's TAP interface, but a few seconds later dnsmasq, as
    # part of handling the VM's DHCP request, overwrites that with a non-permanent
    # (STALE) entry.  Felix only refreshes its permanent ARP programming every 90s by
    # default (RouteRefreshInterval), on a cycle that is not aligned with VM creation,
    # so the permanent entry is not restored until up to 90-120s after the VM was
    # created.  Connectivity in that window is unreliable rather than absent, because a
    # STALE entry is still usable: it only fails if the entry ages out and the kernel's
    # re-ARP gets no answer, as it won't from a VM that ignores ARP requests from the
    # hypervisor.

    @classmethod
    def setUpClass(cls):
        # Allow ingress to all VMs from this test node - so that the test node will be
        # able to ping.
        #
        # For this particular test it's important to set up the following policy BEFORE
        # creating the VMs.  If we create the policy AFTER the VMs, Felix sees the VM
        # endpoints as being updated (because of the added policy) and reprograms the
        # permanent ARPs for them in response to that update.  That would defeat the
        # purpose of this test, which is to verify if Felix recovers the situation when
        # the ARP programming becomes STALE after the initial creation of the VMs, and
        # there are no following policy updates.
        #
        # That also means working out the test node's IP ourselves, because the
        # superclass setUpClass() only does that when it runs, which is too late.
        test_node_ip = LAYOUT.test_node_ip or osutils.get_local_ip(4)
        allow_test_node = {
            "selector": "all()",
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "nets": [test_node_ip + "/32"],
                    },
                },
            ],
        }
        datamodel_v3.put(
            "GlobalNetworkPolicy", "default.allow_test_node", allow_test_node
        )

        super(TestARPIgnore, cls).setUpClass()

    def test_arp_ignore(self):
        # Configure the VMs to ignore ARP.
        for i in range(len(self.vms)):
            result = self.vms[i].execute(
                "sudo sysctl -w net.ipv4.conf.eth0.arp_ignore=2"
            )
            self.assertEqual(result.return_code, 0)

        def check_arp_state():
            # For debugging, check the ARP state on each compute node.
            for node in LAYOUT.compute_nodes:
                node.execute('ip neigh | grep "dev tap"')

        check_arp_state()

        successful_ping_count = 0
        start_time = time.time()
        ping_interval = 5
        required_successful_pings = 60 // ping_interval
        max_duration = 240
        ignored_initial_window = 60
        debug_interval_count = 0
        while (
            time.time() <= start_time + max_duration
            and successful_ping_count < required_successful_pings
        ):
            pings_succeeded_this_time = True
            for i in range(len(self.vms)):
                try:
                    _log.info(
                        "Ping VM #%d successful_ping_count=%d T=%ds",
                        i,
                        successful_ping_count,
                        int(time.time() - start_time),
                    )
                    subprocess.check_call(
                        ["ping", "-c", "1", "-W", "1", str(self.vms[i].get_ip_addr())]
                    )
                except subprocess.CalledProcessError:
                    pings_succeeded_this_time = False

            if (
                pings_succeeded_this_time
                and time.time() > start_time + ignored_initial_window
            ):
                successful_ping_count += 1
            else:
                successful_ping_count = 0

            time.sleep(ping_interval)

            debug_interval_count += 1
            if debug_interval_count >= 6:
                check_arp_state()
                debug_interval_count = 0

        self.assertGreaterEqual(successful_ping_count, required_successful_pings)

    @classmethod
    def tearDownClass(cls):
        datamodel_v3.delete("GlobalNetworkPolicy", "default.allow_test_node")
        super(TestARPIgnore, cls).tearDownClass()
