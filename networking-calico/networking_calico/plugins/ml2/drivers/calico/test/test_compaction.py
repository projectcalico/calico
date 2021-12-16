# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
"""
Test compaction code.
"""

import logging
import mock
import os
import unittest

from etcd3gw.exceptions import Etcd3Exception

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib

from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico import mech_calico


LOG = logging.getLogger(__name__)


class MockLease(object):

    def __init__(self, id, client):
        self.id = id

    def ttl(self):
        if self.id == 1:
            # A reasonable TTL.
            return 30
        else:
            # An unreasonably large TTL.
            return 30000000


class TestCompaction(unittest.TestCase):

    def setUp(self):
        super(TestCompaction, self).setUp()

        # Hook the etcd3gw client.
        etcdv3._client = self.client = mock.Mock()
        # Writes succeed by default.
        self.client.put.return_value = True
        # Insinuate our mock lease class.
        etcdv3.Lease = MockLease

        # Hook relevant logging.
        import logging
        for module in [
                mech_calico,
                etcdv3,
        ]:
            module.LOG = logging.getLogger("\t%-15s\t" %
                                           module.__name__.split('.')[-1])

        self.pid = str(os.getpid())

        # Provide default config.
        lib.m_compat.cfg.CONF.calico.etcd_compaction_period_mins = 60
        lib.m_compat.cfg.CONF.calico.etcd_compaction_min_revisions = 1000

    def tearDown(self):
        etcdv3._client = None
        super(TestCompaction, self).tearDown()

    def test_iter_1(self):
        LOG.info("1. no compaction keys present")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last: not found.
            [],
        ])
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_iter_2(self):
        LOG.info("2. compacted@0 checked@10 now=100 => no compaction")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('0'.encode(), {'mod_revision': '10'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '100',
        }}
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_iter_3(self):
        LOG.info("3. compacted@0 checked@100 now=300 => no compaction")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('0'.encode(), {'mod_revision': '100'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '300',
        }}
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_iter_4(self):
        LOG.info("4. compacted@0 checked@300 now=1100 => compact@100")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('0'.encode(), {'mod_revision': '300'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '1100',
        }}
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '100', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_called()

    def test_iter_5(self):
        LOG.info("5. compacted@100 checked@1100 now=1200 => compact@200")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('100'.encode(), {'mod_revision': '1100'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '1200',
        }}
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '200', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_called()

    def test_trigger_present(self):
        LOG.info("Trigger present; nothing happens")
        self.client.get.side_effect = iter([
            # Read trigger: present with good lease.
            [(self.pid.encode(), {'mod_revision': '2000', 'lease': '1'})],
        ])
        mech_calico.check_request_etcd_compaction()
        self.client.status.assert_not_called()
        self.client.put.assert_not_called()
        self.client.post.assert_not_called()

    def test_trigger_present_missing_lease(self):
        LOG.info("Trigger present but with missing lease")
        self.client.get.side_effect = iter([
            # Read trigger: present but lease missing.
            [(self.pid.encode(), {'mod_revision': '2000'})],
        ])
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_trigger_present_bad_lease(self):
        LOG.info("Trigger present but with bad lease")
        self.client.get.side_effect = iter([
            # Read trigger: present but lease has unreasonably large TTL.
            [(self.pid.encode(), {'mod_revision': '2000', 'lease': '2'})],
        ])
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_bogus_last_compaction_rev(self):
        LOG.info("Bogus last compaction revision > current revision")
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('3000'.encode(), {'mod_revision': '1100'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '1200',
        }}
        mech_calico.check_request_etcd_compaction()
        self.assertEqual([
            mock.call('/calico/compaction/v1/last', '0', lease=None),
            mock.call('/calico/compaction/v1/trigger',
                      self.pid,
                      lease=mock.ANY),
        ],
            self.client.put.mock_calls
        )
        self.client.post.assert_not_called()

    def test_exception_detail_logging(self):
        LOG.info("Logging detail for etcd3 failure exception")

        # This is like test_iter_5, except we arrange for the
        # etcdv3.request_compaction call to raise an exception, and
        # check the resulting logging.
        e3e = Etcd3Exception('revision has been compacted')
        self.client.post.side_effect = e3e
        self.client.get.side_effect = iter([
            # Read trigger: not found.
            [],
            # Read last.
            [('100'.encode(), {'mod_revision': '1100'})],
        ])
        self.client.status.return_value = {'header': {
            'cluster_id': '12345',
            'revision': '1200',
        }}

        with mock.patch.object(
                mech_calico.LOG,
                'info') as mock_li:
            mech_calico.check_request_etcd_compaction()
            self.assertEqual([
                mock.call('/calico/compaction/v1/last', '1200', lease=None),
                mock.call('/calico/compaction/v1/trigger',
                          self.pid,
                          lease=mock.ANY),
                ],
                self.client.put.mock_calls
            )
            self.client.post.assert_called()
            mock_li.assert_called_with(
                'Someone else has requested etcd compaction:\n%s',
                'revision has been compacted',
            )
