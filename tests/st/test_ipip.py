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
from unittest import skip

from test_base import TestBase

"""
Test calico IPIP behaviour

This needs to be a multihost test (so there is actually a cross-host tunnel).
TODO - how do we actually assert that traffic is encapsulated. Maybe packet
capture?
"""


class TestIPIP(TestBase):
    @skip("Not written yet")
    def test_ipip(self):
        pass
