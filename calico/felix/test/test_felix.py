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
felix.test.test_felix
~~~~~~~~~~~

Top level tests for Felix.
"""
import sys
import unittest

# Hide iptc, since we do not have it.
sys.modules['iptc'] = __import__('calico.felix.test.stub_empty')

# Replace calico.felix.fiptables with calico.felix.test.stub_fiptables
import calico.felix.test.stub_fiptables
sys.modules['calico.felix.fiptables'] = __import__('calico.felix.test.stub_fiptables')
calico.felix.fiptables = calico.felix.test.stub_fiptables

# Now import felix, and away we go.
import calico.felix.felix as felix

class TestBasic(unittest.TestCase):
    def test_startup(self):
        config_path = "calico/felix/data/felix_debug.cfg"

        felix.default_logging()
        agent = felix.FelixAgent(config_path)
