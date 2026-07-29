# Copyright 2019 Tigera, Inc. All rights reserved.
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

import json
import logging
from collections import namedtuple

from etcd3gw.exceptions import Etcd3Exception

import mock

from neutron.tests import base

from networking_calico.agent.dhcp_agent import SubnetWatcher
from networking_calico.etcdutils import EtcdWatcher


LOG = logging.getLogger(__name__)

EtcdResponse = namedtuple("EtcdResponse", ["value"])


class TestSubnetWatcher(base.BaseTestCase):

    @mock.patch.object(EtcdWatcher, "start")
    def test_exception_detail_logging(self, loop_fn):

        # Make EtcdWatcher.start throw an exception with detail text.
        loop_fn.side_effect = Etcd3Exception(detail_text="from test_exception_detail")

        with mock.patch.object(
            logging.getLogger("networking_calico.agent.dhcp_agent"), "exception"
        ) as mock_le:
            # Create the DHCP agent and allow it to start the
            # SubnetWatcher loop.
            sw = SubnetWatcher(mock.Mock(), "/calico")
            try:
                sw.start()
            except Exception:
                pass
            mock_le.assert_called_with(
                "Etcd3Exception in SubnetWatcher.start():\n%s",
                "from test_exception_detail",
            )

    def test_snapshot_reconciliation(self):
        # Deletion events can be missed, so SubnetWatcher must discard any
        # subnet that a snapshot no longer reports.
        sw = SubnetWatcher(mock.Mock(), "/calico/dhcp/v2/no-region/subnet")

        def set_subnet(subnet_id):
            sw.on_subnet_set(
                EtcdResponse(
                    value=json.dumps(
                        {
                            "network_id": "net-1",
                            "cidr": "10.65.0.0/24",
                            "gateway_ip": "10.65.0.1",
                        }
                    )
                ),
                subnet_id,
            )

        # Learn two subnets from watch events.
        set_subnet("subnet-a")
        set_subnet("subnet-b")
        self.assertEqual({"subnet-a", "subnet-b"}, set(sw.subnets_by_id.keys()))

        # Process a snapshot that reports subnet-b again, plus a new
        # subnet-c, but not subnet-a - as when subnet-a's deletion event was
        # missed.  subnet-a must be discarded; the others must survive.
        snapshot_data = sw._pre_snapshot_hook()
        set_subnet("subnet-b")
        set_subnet("subnet-c")
        sw._post_snapshot_hook(snapshot_data)
        self.assertEqual({"subnet-b", "subnet-c"}, set(sw.subnets_by_id.keys()))

        # An ordinary deletion event still works, whether or not the subnet
        # is known.
        sw.on_subnet_del(None, "subnet-b")
        sw.on_subnet_del(None, "subnet-never-seen")
        self.assertEqual({"subnet-c"}, set(sw.subnets_by_id.keys()))
