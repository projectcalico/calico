# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
test.test_datamodel_v1
~~~~~~~~~~~~~~~~~~~~~~

Test data model key calculations etc.
"""

import logging
import unittest

from networking_calico.datamodel_v1 import WloadEndpointId


# Logger
log = logging.getLogger(__name__)


class TestWorkloadEndpointId(unittest.TestCase):

    def test_equality(self):
        ep_id = WloadEndpointId("localhost", "orchestrator", "workload",
                                "endpoint")
        self.assertTrue(ep_id == ep_id)
        self.assertFalse(ep_id != ep_id)

        self.assertFalse(ep_id == "not an endpoint id")
        self.assertFalse(ep_id == 42)

        bad_host_ep_id = WloadEndpointId("notlocalhost", "orchestrator",
                                         "workload", "endpoint")
        self.assertFalse(ep_id == bad_host_ep_id)

        bad_orchestrator_ep_id = WloadEndpointId("hostname",
                                                 "notanorchestrator",
                                                 "workload",
                                                 "endpoint")
        self.assertFalse(ep_id == bad_orchestrator_ep_id)

        bad_workload_ep_id = WloadEndpointId("hostname", "orchestrator",
                                             "notworkload", "endpoint")
        self.assertFalse(ep_id == bad_workload_ep_id)

        bad_endpoint_ep_id = WloadEndpointId("hostname", "orchestrator",
                                             "workload", "notanendpoint")
        self.assertFalse(ep_id == bad_endpoint_ep_id)
        self.assertTrue(ep_id != bad_endpoint_ep_id)
