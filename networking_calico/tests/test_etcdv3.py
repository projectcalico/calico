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

from networking_calico.compat import log
from networking_calico import etcdv3

from etcd3gw.exceptions import Etcd3Exception


LOG = logging.getLogger(__name__)


class TestEtcdv3(base.BaseTestCase):

    def test_exception_detail_logging(self):

        e3e = Etcd3Exception(detail_text='from test_exception_detail_logging')

        def fn(self, *args, **kwargs):
            raise e3e

        wrapped = etcdv3.logging_exceptions(fn)

        with mock.patch.object(
                log.getLogger('networking_calico.etcdv3'),
                'warning') as mock_lw:
            try:
                wrapped(None)
            except Exception:
                pass
            mock_lw.assert_called_with(
                "Etcd3Exception, re-raising: %r:\n%s",
                e3e,
                'from test_exception_detail_logging'
            )
