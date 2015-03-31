from netaddr import IPNetwork
from node.adapter import datastore
from nose.tools import assert_equal, assert_true
from node.adapter.ipam import SequentialAssignment

pool = IPNetwork("192.168.0.0/16")
client = datastore.DatastoreClient()

class TestIPAM:
    def setup(self):
        client.remove_all_data()

    def test_get_empty_assignments(self):
        assert_equal(client.get_assigned_addresses(pool),
                     {})

    def test_add_assignment(self):
        none_assigned = client.get_assigned_addresses(pool)
        assert_equal(none_assigned, {})

        one_assigned = {"192.168.0.1": ""}
        assert_true(client.update_assigned_address(pool, {}, one_assigned))
        assert_equal(client.get_assigned_addresses(pool), one_assigned)

    def test_sequential_assignment(self):
        assigner = SequentialAssignment()
        assert_equal("192.168.0.1", assigner.allocate(pool))

    def test_sequential_assignment_tiny_pool(self):
        assigner = SequentialAssignment()
        assert_equal(None, assigner.allocate(IPNetwork("192.168.0.0/31")))

    def test_sequential_assignment_full_pool(self):
        four_pool = IPNetwork("192.168.0.0/30")
        assigner = SequentialAssignment()

        assert_equal("192.168.0.1", assigner.allocate(four_pool))
        assert_equal("192.168.0.2", assigner.allocate(four_pool))
        assert_equal(None, assigner.allocate(four_pool))

