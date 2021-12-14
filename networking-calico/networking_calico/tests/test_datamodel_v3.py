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

import logging
import unittest

from networking_calico import datamodel_v3


# Logger
log = logging.getLogger(__name__)


class TestDatamodelV3(unittest.TestCase):

    def test_sanitize(self):

        s = datamodel_v3.sanitize_label_name_value(
            "simple", 100)
        self.assertEqual(s, "simple")

        s = datamodel_v3.sanitize_label_name_value(
            "/calico/v1/policy/profile/prof1/rules", 100)
        self.assertEqual(s, "calico_v1_policy_profile_prof1_rules")

        s = datamodel_v3.sanitize_label_name_value("Dan's Project", 100)
        self.assertEqual(s, "Dan_s_Project")

        s = datamodel_v3.sanitize_label_name_value("_-+.934abc%_-", 100)
        self.assertEqual(s, "934abc")

        s = datamodel_v3.sanitize_label_name_value(
            "simple", 10)
        self.assertEqual(s, "simple")

        s = datamodel_v3.sanitize_label_name_value(
            "/calico/v1/policy/profile/prof1/rules", 10)
        self.assertEqual(s, "calico_v1")

        s = datamodel_v3.sanitize_label_name_value("Dan's Project", 10)
        self.assertEqual(s, "Dan_s_Proj")

        s = datamodel_v3.sanitize_label_name_value("_-+.934abc%_-", 10)
        self.assertEqual(s, "934abc")
