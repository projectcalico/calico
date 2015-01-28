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


class StubNetworkSubscriber(object):
    """
    Stub version of the Network Subscriber class.

    The methods prefixed test_ are for unit test script use.
    """

    def __init__(self, network_store):
        self.network_store = network_store

    def test_update_group(self, group_uuid, members, rules):
        """
        Pass a group update message to the Network Store.

        - group_uuid: The UUID of the group to create / update
        - members: A dictionary {endpoint_uuid: [endpoint IPs], ...}
        - rules: A rules object (see Calico API Proposal)
        """
        self.network_store.update_group(group_uuid, members, rules)
