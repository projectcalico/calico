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

import unittest
import time
import threading
from copy import deepcopy

from stub_acl_publisher import StubACLPublisher
from stub_processor import StubRuleProcessor

from calico.acl_manager.acl_store import ACLStore
import calico.acl_manager.utils as utils


class TestACLStore(unittest.TestCase):
    """Unit tests for the ACLStore class."""

    def setUp(self):
        self.acl_store = ACLStore()
        self.processor = StubRuleProcessor(self, None, self.acl_store)
        self.acl_pub = StubACLPublisher(self, self.acl_store)
        self.acl_store.start(self.acl_pub)

    def tearDown(self):
        self.acl_store.stop()
        self.acl_store = None
        self.acl_pub = None
        self.processor = None

    acls = {'v4': {'inbound': [{'group': None,
                                'cidr': '10.2.3.0/24',
                                'port': None,
                                'protocol': None}],
                   'inbound_default': 'deny',
                   'outbound': [{'group': None,
                                 'cidr': '10.1.1.1/32',
                                 'port': '4',
                                 'protocol': 'udp'}],
                   'outbound_default': 'deny'},
            'v6': {'inbound': [],
                   'inbound_default': 'deny',
                   'outbound': [{'group': None,
                                 'cidr': 'fd5f::1/128',
                                 'port': None,
                                 'protocol': None}],
                   'outbound_default': 'deny'}}

    def test_case1(self):
        """
        Test ACL Store updates.

        - Creating and modifying ACLs for an endpoint
        """
        # Add new ACLs for an endpoint
        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

        # Modify those ACLs
        self.acls['v4']['inbound'][0]['port'] = 22
        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

    def test_case2(self):
        """
        Test ACL Store query handling.

        - Query known and unknown endpoints
        """
        # Query when there are no known endpoints
        self.acl_pub.test_query_endpoint_acls('e1')
        self.acl_pub.test_wait_assert_all_acls_received()

        # Add some ACLs
        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

        # Query a known endpoint
        self.acl_pub.test_query_endpoint_acls('e1')
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

        # Query an unknown endpoint
        self.acl_pub.test_query_endpoint_acls('e5')
        self.acl_pub.test_wait_assert_all_acls_received()

    def test_case3(self):
        """
        Clean shutdown of ACL Manager on ACL Store worker thread crash
        """
        # Patch the terminate function so the tests don't exit
        terminate_called = threading.Event()
        def _terminate(exit_code=1):
            terminate_called.set()
        utils.terminate = _terminate

        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_raise_exception()

        # Allow three seconds for the worker thread to call terminate
        terminate_called.wait(3)
        self.acl_pub.test_wait_assert_all_acls_received()

    def test_case4(self):
        """
        Check ACL Store suppresses superfluous no-op updates
        """
        # Add some ACLs - an update is published
        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

        # Update the same ACLs without changing them
        self.processor.test_update_endpoint_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

        # Now query the ACLs to check they're still returned
        self.acl_pub.test_query_endpoint_acls('e1')
        self.acl_pub.test_set_expected_acls('e1', self.acls)
        self.acl_pub.test_wait_assert_all_acls_received()

if __name__ == '__main__':
    unittest.main()
