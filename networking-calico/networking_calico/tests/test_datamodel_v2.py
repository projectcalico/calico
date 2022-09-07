# -*- coding: utf-8 -*-
# Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
import unittest

from networking_calico import datamodel_v2


# Logger
log = logging.getLogger(__name__)


class TestDatamodelV2(unittest.TestCase):

    def test_network_paths(self):

        s = datamodel_v2.network_dir()
        self.assertEqual(s, "/calico/dhcp/v2/no-region/network")

        s = datamodel_v2.network_dir("district13")
        self.assertEqual(s, "/calico/dhcp/v2/district13/network")

        s = datamodel_v2.key_for_network("abc12456", datamodel_v2.NO_REGION)
        self.assertEqual(s, "/calico/dhcp/v2/no-region/network/abc12456")

        s = datamodel_v2.key_for_network("abc12456", "district13")
        self.assertEqual(s, "/calico/dhcp/v2/district13/network/abc12456")
