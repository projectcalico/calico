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
import unittest

from nose.tools import assert_equal, assert_true, assert_false

from libnetwork_plugin.datastore_libnetwork import LibnetworkDatastoreClient

# We test using a real etcd back end.
client = LibnetworkDatastoreClient()

TEST_ENDPOINT_ID = "abcdefg123456"


class TestLibnetworkDatastoreClient(unittest.TestCase):

    def setUp(self):
        client.remove_all_data()

    def test_cnm_endpoint_read_write(self):
        """
        Test reading and writing an CNM endpoint.
        """
        data = {"test": 1, "test2": 2}

        # Endpoint should not exist at first, attempts to read it return None.
        assert_false(client.cnm_endpoint_exists(TEST_ENDPOINT_ID))
        assert_equal(client.read_cnm_endpoint(TEST_ENDPOINT_ID), None)

        # Write an endpoint into etcd.
        client.write_cnm_endpoint(TEST_ENDPOINT_ID, data)

        # Endpoint now exists, check stored data.
        assert_true(client.cnm_endpoint_exists(TEST_ENDPOINT_ID))
        self.assertDictEqual(client.read_cnm_endpoint(TEST_ENDPOINT_ID),
                               data)

    def test_cnm_endpoint_write_delete(self):
        """
        Test writing and deleting an CNM endpoint.
        """
        data = {"test": 1, "test2": 2}

        # Endpoint should not exist at first, so create it.
        assert_false(client.cnm_endpoint_exists(TEST_ENDPOINT_ID))
        client.write_cnm_endpoint(TEST_ENDPOINT_ID, data)

        # Endpoint now exists, delete it.
        assert_true(client.cnm_endpoint_exists(TEST_ENDPOINT_ID))
        assert_true(client.delete_cnm_endpoint(TEST_ENDPOINT_ID))

        # Endpoint should not exist.
        assert_false(client.cnm_endpoint_exists(TEST_ENDPOINT_ID))
        assert_equal(client.read_cnm_endpoint(TEST_ENDPOINT_ID), None)

        # Deleting the endpoint again will return False, indicating no
        # endpoint.
        assert_false(client.delete_cnm_endpoint(TEST_ENDPOINT_ID))
