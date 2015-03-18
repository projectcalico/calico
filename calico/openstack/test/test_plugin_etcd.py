# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
openstack.test.test_plugin_etcd
~~~~~~~~~~~

Unit test for the Calico/OpenStack Plugin using etcd transport.
"""
import unittest

import calico.openstack.test.lib as lib
import calico.openstack.mech_calico as mech_calico


class TestPluginEtcd(lib.Lib, unittest.TestCase):

    # Setup before each test case (= each method below whose name begins with
    # "test").
    def setUp(self):
        super(TestPluginEtcd, self).setUp()

    def start_of_day(self):
        # Tell the driver to initialize.
        self.driver.initialize()

    # Mainline test.
    def test_mainline(self):
        # Start of day processing: initialization and socket binding.
        self.start_of_day()
