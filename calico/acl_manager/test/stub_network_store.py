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


class StubNetworkStore(object):
    """
    Stub version of the Network Store class.

    The methods prefixed test_ are for unit test script use.
    """

    def __init__(self):
        self.test_groups = []
        self.test_group_members = {}
        self.test_group_rules = {}

    def get_groups(self):
        return self.test_groups

    def get_group_members(self, group_uuid):
        return self.test_group_members[group_uuid]

    def get_group_rules(self, group_uuid):
        return self.test_group_rules[group_uuid]

    def test_set_groups(self, groups):
        """
        Set the groups returned by get_groups().

        - groups: A list of group UUIDs
        """
        self.test_groups = groups

    def test_set_group_members(self, group_uuid, group_members):
        """
        Set the group members returned by get_group_members().

        - group_uuid: The group UUID to update the membership of
        - group_members: A dictionary endpoint_uuid => [endpoint's IPs]
        """
        self.test_group_members[group_uuid] = group_members

    def test_set_group_rules(self, group_uuid, group_rules):
        """
        Set the rules returned by get_group_rules().

        - group_uuid: The group UUID to update the fules for
        - group_rules: A rules object (see Calico API Proposal)
        """
        self.test_group_rules[group_uuid] = group_rules
