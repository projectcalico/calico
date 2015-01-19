# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
felix.test.test_endpoint
~~~~~~~~~~~~~~~~~~~~~~~~

Test the endpoint handling code.
"""
import mock
import sys
import unittest
import uuid

import calico.felix.devices as devices

# Stub out the iptables code.
import calico.felix.test.stub_fiptables
sys.modules['calico.felix.fiptables'] = __import__('calico.felix.test.stub_fiptables')
calico.felix.fiptables = calico.felix.test.stub_fiptables

import calico.felix.endpoint as endpoint

class TestEndpoint(unittest.TestCase):
    def test_program_bails_early(self):
        """
        Test that programming an endpoint fails early if the endpoint is down.
        """
        devices.interface_up = mock.MagicMock()
        devices.interface_up.return_value = False

        ep = endpoint.Endpoint(str(uuid.uuid4()), 'aa:bb:cc:dd:ee:ff')
        retval = ep.program_endpoint()

        self.assertFalse(retval)
