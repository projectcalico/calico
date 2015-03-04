# Copyright 2014 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
from copy import deepcopy

from stub_net_subscriber import StubNetworkSubscriber
from stub_processor import StubRuleProcessor

from calico.acl_manager.net_store import NetworkStore

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


class TestNetworkStore(unittest.TestCase):
    """Unit tests for the NetworkStore class."""

    def setUp(self):
        self.net_store = NetworkStore()
        self.net_sub = StubNetworkSubscriber(self.net_store)
        self.processor = StubRuleProcessor(self, self.net_store, None)

        self.net_store.add_processor(self.processor)

    def tearDown(self):
        self.net_store = None
        self.net_sub = None
        self.processor = None

    empty_rules = {'inbound': [],
                   'outbound': [],
                   'inbound_default': 'deny',
                   'outbound_default': 'deny'}

    def test_case1(self):
        """
        Test the Network Store with a single group.

        - Creating, modifying and deleting a group
        - Get the membership of a deleted or non-existent group
        """
        # Create a new group
        g1_members = {'e1': ['10.1.1.1']}
        g1_rules = deepcopy(self.empty_rules)
        exp_state = {'g1': {'members': g1_members, 'rules': g1_rules}}
        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()

        # Update that group
        g1_members['e2'] = ['fd5f:1::1', '10.2.3.4']
        g1_rules['inbound'].append({'group': 'g2',
                                    'cidr': None,
                                    'protocol': 'tcp',
                                    'port': '443'})
        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()

        # Delete the group (by removing all its members)
        g1_members.clear()
        self.processor.test_queue_expected_recalc({})
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()

        # It is valid to query the membership of a deleted or never-existed
        # group, because it may be referred to by rules in other groups.
        self.assertEqual(self.net_store.get_group_members('g1'), {})
        self.assertEqual(self.net_store.get_group_members('never'), {})

        # Resend the delete - this should be a no-op
        self.processor.test_queue_expected_recalc({})
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()

    def test_case2(self):
        """
        Test the Network Store with multiple groups.

        - Add and remove multiple groups
        """
        # Create 2 new groups
        g1_members = {'e1': ['10.1.1.1']}
        g1_rules = deepcopy(self.empty_rules)
        g2_members = {'e2': ['10.1.1.2']}
        g2_rules = deepcopy(self.empty_rules)
        exp_state = {'g1': {'members': g1_members, 'rules': g1_rules}}

        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()

        exp_state['g2'] = {'members': g2_members, 'rules': g2_rules}
        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g2', g2_members, g2_rules)
        self.processor.test_assert_recalcs_done()

        # Modify a group
        g2_members['e2'].append('fd5f:7::')
        g2_members['e3'] = ['10.2.2.2']
        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g2', g2_members, g2_rules)
        self.processor.test_assert_recalcs_done()

        # Delete the groups
        g1_members.clear()
        del exp_state['g1']
        self.processor.test_queue_expected_recalc(exp_state)
        self.net_sub.test_update_group('g1', g1_members, g1_rules)
        self.processor.test_assert_recalcs_done()
        self.assertEqual(self.net_store.get_group_members('g1'), {})

        g2_members.clear()
        self.processor.test_queue_expected_recalc({})
        self.net_sub.test_update_group('g2', g2_members, g2_rules)
        self.processor.test_assert_recalcs_done()
        self.assertEqual(self.net_store.get_group_members('g2'), {})

if __name__ == '__main__':
    unittest.main()
