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

from copy import deepcopy


class StubRuleProcessor(object):
    """
    Stub version of the Rule Processor class.

    The methods prefixed test_ are for unit test script use.
    """

    def __init__(self, test_case, net_store, acl_store):
        """
        Create a stub Rule Processor.

        - test_case: The test case, used to call unittest assert methods
        - net_store: The network store under test
        """
        self.test_case = test_case
        self.net_store = net_store
        self.acl_store = acl_store
        self.expected_recalcs = []

    def recalc_rules(self):
        exp_state = self.expected_recalcs.pop(0)
        self.test_case.assertItemsEqual(self.net_store.get_groups(),
                                        exp_state.keys())

        for group, exp_state in exp_state.iteritems():
            self.test_case.assertEqual(self.net_store.get_group_members(group),
                                       exp_state['members'])
            self.test_case.assertEqual(self.net_store.get_group_rules(group),
                                       exp_state['rules'])

    def test_queue_expected_recalc(self, exp_network_state):
        """
        Queue up the expected state of the Network Store when it next tells the
        Rule Processor to recalculate ACLs.

        - exp_network_state: The expected state of the network.  This is a
            dictionary, set up as follows:
            {group_uuid: {'members': {endpoint_uuid: [endpoint's IPs], ...},
                          'rules': a Rules object (Calico API Proposal)},
             ...}
        """
        self.expected_recalcs.append(exp_network_state)

    def test_assert_recalcs_done(self):
        """
        Assert that all queued recalcs have been carried out.
        """
        # Assert on the next expected recalc instead of the list length so it's
        # easier to identify what didn't happen.
        if len(self.expected_recalcs) != 0:
            self.test_case.assertEqual(self.expected_recalcs, None)

    def test_update_endpoint_acls(self, endpoint_uuid, acls):
        """
        Pass ACLs to the ACL Store.
        """
        self.acl_store.update_endpoint_rules(endpoint_uuid, deepcopy(acls))
