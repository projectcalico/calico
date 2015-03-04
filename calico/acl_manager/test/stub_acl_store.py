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

from collections import defaultdict


class StubACLStore(object):
    """
    Stub version of the ACL Store class.

    The methods prefixed test_ are for unit test script use.
    """

    def __init__(self, test_case):
        self.test_case = test_case  # Used to call assertEqual etc.
        self.test_endpoint_acls = {}
        self.test_endpoint_acl_changes = defaultdict(int)

    def update_endpoint_rules(self, endpoint_uuid, rules):
        self.test_endpoint_acls[endpoint_uuid] = rules
        self.test_endpoint_acl_changes[endpoint_uuid] += 1

    def test_assert_endpoints(self, endpoint_list):
        """
        Assert that the ACL Store contains the right endpoints.

        - endpoint_list: The list of endpoint UUIDs to check for
        """
        self.test_case.assertItemsEqual(self.test_endpoint_acls.keys(),
                                        endpoint_list)

    def test_assert_endpoint_acls(self, endpoint_uuid, update_count, acls):
        """
        Assert that the ACL Store contains the right ACLs for an endpoint.

        - endpoint_uuid: The endpoint to check the ACLs for
        - update_count: The number of updates made to those ACLs, or None to
            skip this check
        - acls: The ACLs to check for (the ACL collection object on the Calico
            ACL API Proposal)
        """
        # Check that the ACLs for the endpoint have been updated the right
        # number of times.
        if update_count:
            self.test_case.assertEqual(
                self.test_endpoint_acl_changes[endpoint_uuid],
                update_count
            )

        # Check that the ACLs themselves are correct
        ep_acls = self.test_endpoint_acls[endpoint_uuid]
        self.test_case.assertDictEqual(acls, ep_acls)
