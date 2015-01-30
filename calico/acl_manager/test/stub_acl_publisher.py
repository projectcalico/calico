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

from Queue import Queue
import time


class StubACLPublisher(object):
    """
    Stub version of the ACL Publisher class.

    The methods prefixed test_ are for unit test script use.
    """

    def __init__(self, test_case, acl_store):
        self.test_case = test_case
        self.acl_store = acl_store
        self.queue = Queue()
        self.expected_acls = {}
        self.raise_exception = False

    def publish_endpoint_acls(self, endpoint_uuid, acls):
        self.queue.put((endpoint_uuid, acls))
        if self.raise_exception:
            raise Exception("Test exception")

    def test_query_endpoint_acls(self, endpoint_uuid):
        """
        Query the ACLs for an endpoint.

        The ACL Store responds asynchronously, and the expected response is set
        up by test_set_expected_acls() and checked with
        test_wait_assert_all_acls_received().
        """
        self.acl_store.query_endpoint_rules(endpoint_uuid)

    def test_set_expected_acls(self, endpoint_uuid, acls):
        assert endpoint_uuid not in self.expected_acls
        self.expected_acls[endpoint_uuid] = acls

    def test_raise_exception(self):
        self.raise_exception = True

    def test_wait_assert_all_acls_received(self):
        """
        Wait (up to 1 second a set) for the expected ACLs to be received).
        """
        if len(self.expected_acls) == 0:
            # Since the ACL Store runs in a separate thread, wait for it to
            # finish working.
            time.sleep(1)

        while len(self.expected_acls) > 0:
            (endpoint, acls) = self.queue.get(timeout = 1)
            self.test_case.assertTrue(endpoint in self.expected_acls)
            self.test_case.assertEqual(self.expected_acls[endpoint], acls)
            del self.expected_acls[endpoint]

        self.test_case.assertTrue(self.queue.empty())
