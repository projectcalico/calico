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
Test calicoctl pool

1) Test the CRUD aspects of the pool commands.
2) Test IP assignment from pool.

BGP exported routes are hard to test and aren't expected to change much so
write tests for them (yet)

"""


class TestPool(TestBase):
    @skip("Not written yet")
    def test_pool_crud(self):
        """
        Test that a basic CRUD flow for pool commands.
        """
        pass
        # results = host.calicoctl("status")
        # TODO - Add a pool, check it appears in the show, remove a pool check it disappears from the show. IPv4 + IPv6

    @skip("Not written yet")
    def test_pool_ip_assignment(self):
        """
        Test that pools can be used to control IP assignment.
        """
        pass
        # TODO Remove the default, create a new pool. Create a container and check
        #  it gets the IP from the pool.
        # [Needs to be libnetwork based since that uses IPAM]


