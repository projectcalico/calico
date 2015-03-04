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

from stub_network_store import StubNetworkStore
from stub_acl_store import StubACLStore

from calico.acl_manager.processor import RuleProcessor

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


class TestProcessor(unittest.TestCase):
    """Unit tests for the RuleProcessor class."""

    def setUp(self):
        self.network_store = StubNetworkStore()
        self.acl_store = StubACLStore(self)
        self.processor = RuleProcessor(self.acl_store, self.network_store)

    def tearDown(self):
        self.network_store = None
        self.acl_store = None
        self.processor = None

    # Empty rules and ACLs dictionaries.
    empty_rules = {'inbound': [],
                   'outbound': [],
                   'inbound_default': 'deny',
                   'outbound_default': 'deny'}
    empty_acls = {'v4': {'inbound': [],
                         'inbound_default': 'deny',
                         'outbound': [],
                         'outbound_default': 'deny'},
                  'v6': {'inbound': [],
                         'inbound_default': 'deny',
                         'outbound': [],
                         'outbound_default': 'deny'}}

    def test_case1(self):
        """
        Test simple rules with one group <=> one endpoint <=> one IP address.

        - Group, CIDR and absent rules
        - IPv4 and IPv6 addresses
        - Protocols and ports specified and absent
        - Adding, removing and modifying rules
        """
        # Set up the initial network state
        self.network_store.test_set_groups(['g1', 'g2'])
        self.network_store.test_set_group_members('g1', {'e1': ['10.1.1.1']})
        self.network_store.test_set_group_members('g2', {'e2': ['10.1.1.7']})
        g1_rules = {'inbound': [{'group': None,
                                 'cidr': '10.1.3.0/24',
                                 'protocol': None,
                                 'port:': '131'}],
                    'outbound': [{'group': 'g2',
                                  'cidr': None,
                                  'protocol': 'udp',
                                  'port': None}],
                    'inbound_default': 'deny',
                    'outbound_default': 'deny'}
        self.network_store.test_set_group_rules('g1', g1_rules)
        g2_rules = deepcopy(self.empty_rules)
        self.network_store.test_set_group_rules('g2', g2_rules)

        # Tell the processor to recalculate its rules
        self.processor.recalc_rules()

        # Check the ACLs produced
        self.acl_store.test_assert_endpoints(['e1', 'e2'])
        e1_acls = {'v4': {'inbound': [{'cidr': '10.1.3.0/24',
                                       'group': None,
                                       'port:': '131',
                                       'protocol': None}],
                          'inbound_default': 'deny',
                          'outbound': [{'cidr': '10.1.1.7/32',
                                        'group': None,
                                        'port': None,
                                        'protocol': 'udp'}],
                          'outbound_default': 'deny'},
                   'v6': {'inbound': [],
                          'inbound_default': 'deny',
                          'outbound': [],
                          'outbound_default': 'deny'}}
        self.acl_store.test_assert_endpoint_acls('e1', 1, e1_acls)
        e2_acls = deepcopy(self.empty_acls)
        self.acl_store.test_assert_endpoint_acls('e2', 1, e2_acls)

        # Add an additional rule to g1
        g1_rules['inbound'].append({'group': 'g1',
                                    'cidr': None,
                                    'protocol': 'tcp',
                                    'port': '*'})
        self.processor.recalc_rules()

        self.acl_store.test_assert_endpoints(['e1', 'e2'])
        e1_acls['v4']['inbound'].append({'group': None,
                                         'cidr': '10.1.1.1/32',
                                         'protocol': 'tcp',
                                         'port': '*'})
        self.acl_store.test_assert_endpoint_acls('e1', 2, e1_acls)
        # The ACLs for endpoint 2 are recalculated superfluously but harmlessly
        self.acl_store.test_assert_endpoint_acls('e2', 2, e2_acls)


        # Change one of g1's rules into an IPv6 CIDR rule
        g1_rules['outbound'][0] = {'group': None,
                                   'cidr': 'fd5f:1::7/96',
                                   'protocol': 'tcp',
                                   'port': '80'}
        self.processor.recalc_rules()

        self.acl_store.test_assert_endpoints(['e1', 'e2'])
        e1_acls['v4']['outbound'] = []
        e1_acls['v6']['outbound'].append({'group': None,
                                         'cidr': 'fd5f:1::7/96',
                                         'protocol': 'tcp',
                                         'port': '80'})
        self.acl_store.test_assert_endpoint_acls('e1', 3, e1_acls)
        self.acl_store.test_assert_endpoint_acls('e2', 3, e2_acls)

        # Remove a rule from g1
        g1_rules['inbound'].pop(0)
        self.processor.recalc_rules()

        self.acl_store.test_assert_endpoints(['e1', 'e2'])
        e1_acls['v4']['inbound'].pop(0)
        self.acl_store.test_assert_endpoint_acls('e1', 4, e1_acls)
        self.acl_store.test_assert_endpoint_acls('e2', 4, e2_acls)

    def test_case2(self):
        """
        Test multiple IPs per endpoint, EPs per group and groups per EP.

        - Adding and removing IPs to endpoints
        - Adding and removing endpoints to groups
        - Adding and removing additional groups to endpoints
        """
        self.network_store.test_set_groups(['g1', 'g2'])
        self.network_store.test_set_group_members('g1', {'e1': ['10.1.1.1',
                                                                '10.1.1.2']})
        self.network_store.test_set_group_members('g2', {'e1': ['10.1.1.1',
                                                                '10.1.1.2'], # change transiently
                                                         'e2': ['10.1.1.7']})
        g1_rules = {'inbound': [],
                    'outbound': [{'group': 'g2',
                                  'cidr': None,
                                  'protocol': None,
                                  'port': None}],
                    'inbound_default': 'deny',
                    'outbound_default': 'deny'}
        self.network_store.test_set_group_rules('g1', g1_rules)
        g2_rules = {'inbound': [{'group': None,
                                 'cidr': 'fd5f:3::/64',
                                 'protocol': None,
                                 'port': None}],
                    'outbound': [],
                    'inbound_default': 'deny',
                    'outbound_default': 'deny'}
        self.network_store.test_set_group_rules('g2', g2_rules)
        self.processor.recalc_rules()

        self.acl_store.test_assert_endpoints(['e1', 'e2'])
        e1_acls = deepcopy(self.empty_acls)
        e1_acls['v6']['inbound'] = [{'group': None,
                                     'cidr': 'fd5f:3::/64',
                                     'protocol': None,
                                     'port': None}]
        e1_acls['v4']['outbound'] = [{'group': None,
                                      'cidr': '10.1.1.1/32',
                                      'protocol': None,
                                      'port': None},
                                     {'group': None,
                                      'cidr': '10.1.1.2/32',
                                      'protocol': None,
                                      'port': None},
                                     {'group': None,
                                      'cidr': '10.1.1.7/32',
                                      'protocol': None,
                                      'port': None}]
        self.acl_store.test_assert_endpoint_acls('e1', 1, e1_acls)

    def test_case3(self):
        """
        Test ignoring empty rules and endpoints.

        - Endpoint UUID ''
        - Empty rule
        """
        # The plugin can pass empty rules or endpoints to ACL Manager, so make
        # sure these work.
        self.network_store.test_set_groups(['g1'])
        self.network_store.test_set_group_members('g1', {'': [],
                                                         'e1': '10.1.1.1'})

        g1_rules = {'inbound': [{'group': None,
                                 'cidr': None,
                                 'protocol': None,
                                 'port:': None}],
                    'outbound': [{'group': None,
                                  'cidr': '10.2.0.0/16',
                                  'protocol': None,
                                  'port': '12'}],
                    'inbound_default': 'deny',
                    'outbound_default': 'deny'}
        self.network_store.test_set_group_rules('g1', g1_rules)

        # Tell the processor to recalculate its rules
        self.processor.recalc_rules()

        # Check the ACLs produced
        self.acl_store.test_assert_endpoints(['e1'])
        e1_acls = {'v4': {'inbound': [],
                          'inbound_default': 'deny',
                          'outbound': [{'cidr': '10.2.0.0/16',
                                        'group': None,
                                        'port': '12',
                                        'protocol': None}],
                          'outbound_default': 'deny'},
                   'v6': {'inbound': [],
                          'inbound_default': 'deny',
                          'outbound': [],
                          'outbound_default': 'deny'}}
        self.acl_store.test_assert_endpoint_acls('e1', 1, e1_acls)

    def test_case4(self):
        """
        Test rule which refers to an unknown group.
        """
        # Rules can target another group, but that group may have no members.
        self.network_store.test_set_groups(['g1'])
        self.network_store.test_set_group_members('g1', {'e1': '10.1.1.1'})
        self.network_store.test_set_group_rules('g1',
                                                {'inbound': [{'group': 'g2',
                                                              'cidr': None,
                                                              'protocol': None,
                                                              'port': None}],
                                                 'outbound': [],
                                                 'inbound_default': 'deny',
                                                 'outbound_default': 'deny'})
        self.processor.recalc_rules()
        self.acl_store.test_assert_endpoints(['e1'])
        self.acl_store.test_assert_endpoint_acls('e1', 1, self.empty_acls)


if __name__ == '__main__':
    unittest.main()
