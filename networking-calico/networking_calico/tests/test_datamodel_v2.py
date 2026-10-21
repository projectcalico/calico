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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from networking_calico import datamodel_v2


class TestPortStatusId(unittest.TestCase):

    def setUp(self):
        super().setUp()
        datamodel_v2._reset_globals()

    def tearDown(self):
        datamodel_v2._reset_globals()
        super().tearDown()

    def _decode(self, region_string, key):
        return datamodel_v2.get_port_status_id_from_key(region_string, key)

    def test_openstack_port_status_key(self):
        self.assertEqual(
            self._decode(
                "no-region",
                "/calico/felix/v2/no-region/host/felix-host-1/workload/openstack/"
                "openstack%2fvm-1/endpoint/port-1",
            ),
            datamodel_v2.PortStatusId("felix-host-1", "vm-1", "port-1"),
        )

    def test_regional_namespace(self):
        self.assertEqual(
            self._decode(
                "region-east",
                "/calico/felix/v2/region-east/host/h/workload/openstack/"
                "openstack-region-east%2fvm-1/endpoint/port-1",
            ),
            datamodel_v2.PortStatusId("h", "vm-1", "port-1"),
        )

    def test_not_in_felix_openstack_form(self):
        for key in [
            # No namespace in the workload segment.
            "/calico/felix/v2/no-region/host/h/workload/openstack/vm-1/endpoint/p",
            # No device_id after it.
            (
                "/calico/felix/v2/no-region/host/h/workload/openstack/"
                "openstack%2f/endpoint/p"
            ),
            # Not an endpoint status key at all.
            "/calico/felix/v2/no-region/host/h/status",
        ]:
            self.assertIsNone(self._decode("no-region", key), key)
