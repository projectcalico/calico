# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
import mock
import unittest

from calico.datamodel_v1 import *


# Logger
log = logging.getLogger(__name__)


class TestDatamodel(unittest.TestCase):
    def test_rules_regex(self):
        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rules")
        self.assertEqual(m.group("profile_id"), "prof1")
        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rules/")
        self.assertEqual(m.group("profile_id"), "prof1")

        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rule")
        self.assertFalse(m)
        m = RULES_KEY_RE.match("/calico/v1/host/")
        self.assertFalse(m)

    def test_dir_for_host(self):
        self.assertEqual(dir_for_host("foo"), "/calico/v1/host/foo")

    def test_dir_for_per_host_config(self):
        self.assertEqual(dir_for_per_host_config("foo"),
                         "/calico/v1/host/foo/config")

    def test_key_for_endpoint(self):
        self.assertEqual(
            key_for_endpoint("foo", "openstack", "wl1", "ep2"),
            "/calico/v1/host/foo/workload/openstack/wl1/endpoint/ep2")

    def test_key_for_profile(self):
        self.assertEqual(key_for_profile("prof1"),
                         "/calico/v1/policy/profile/prof1")

    def test_key_for_profile_rules(self):
        self.assertEqual(key_for_profile_rules("prof1"),
                         "/calico/v1/policy/profile/prof1/rules")

    def test_key_for_profile_tags(self):
        self.assertEqual(key_for_profile_tags("prof1"),
                         "/calico/v1/policy/profile/prof1/tags")

    def test_key_for_config(self):
        self.assertEqual(key_for_config("ConfigValue"),
                         "/calico/v1/config/ConfigValue")

    def test_get_profile_id(self):
        self.assertEqual(
            get_profile_id_for_profile_dir("/calico/v1/policy/profile/prof1"),
            "prof1")
        self.assertEqual(
            get_profile_id_for_profile_dir("/calico/v1/policy/profile/prof1/"),
            "prof1")
        self.assertEqual(get_profile_id_for_profile_dir(""), None)

    def test_get_profile_id_non_profile(self):
        self.assertEquals(
            get_profile_id_for_profile_dir("/calico"), None)
        self.assertEquals(
            get_profile_id_for_profile_dir("/calico/foo"), None)
        self.assertEquals(
            get_profile_id_for_profile_dir("/calico/v1/policy/profile/prof1/rules"), None)


class TestEndpointId(unittest.TestCase):

    def test_equality(self):
        ep_id = EndpointId("localhost", "orchestrator", "workload", "endpoint")
        self.assertTrue(ep_id == ep_id)
        self.assertFalse(ep_id != ep_id)

        self.assertFalse(ep_id == "not an endpoint id")
        self.assertFalse(ep_id == 42)

        bad_host_ep_id = EndpointId("notlocalhost", "orchestrator",
                                    "workload", "endpoint")
        self.assertFalse(ep_id == bad_host_ep_id)

        bad_orchestrator_ep_id = EndpointId("hostname", "notanorchestrator",
                                            "workload", "endpoint")
        self.assertFalse(ep_id == bad_orchestrator_ep_id)

        bad_workload_ep_id = EndpointId("hostname", "orchestrator",
                                        "notworkload", "endpoint")
        self.assertFalse(ep_id == bad_workload_ep_id)

        bad_endpoint_ep_id = EndpointId("hostname", "orchestrator",
                                        "workload", "notanendpoint")
        self.assertFalse(ep_id == bad_endpoint_ep_id)
        self.assertTrue(ep_id != bad_endpoint_ep_id)
