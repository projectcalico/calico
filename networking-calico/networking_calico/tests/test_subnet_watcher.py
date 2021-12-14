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

import logging
import mock

from neutron.tests import base

from networking_calico.agent.dhcp_agent import SubnetWatcher
from networking_calico.etcdutils import EtcdWatcher

from etcd3gw.exceptions import Etcd3Exception


LOG = logging.getLogger(__name__)


class TestSubnetWatcher(base.BaseTestCase):

    @mock.patch.object(EtcdWatcher, 'start')
    def test_exception_detail_logging(self, loop_fn):

        # Make EtcdWatcher.start throw an exception with detail text.
        loop_fn.side_effect = Etcd3Exception(
            detail_text='from test_exception_detail'
        )

        with mock.patch.object(
                logging.getLogger('networking_calico.agent.dhcp_agent'),
                'exception') as mock_le:
            # Create the DHCP agent and allow it to start the
            # SubnetWatcher loop.
            sw = SubnetWatcher(mock.Mock(), "/calico")
            try:
                sw.start()
            except Exception:
                pass
            mock_le.assert_called_with(
                "Etcd3Exception in SubnetWatcher.start():\n%s",
                'from test_exception_detail'
            )
