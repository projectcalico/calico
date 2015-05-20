from netaddr import IPNetwork, IPAddress
from nose.tools import assert_equal, assert_true, assert_false
from calico_containers.adapter.ipam import SequentialAssignment, IPAMClient

pool = IPNetwork("192.168.0.0/16")
client = IPAMClient()

class TestIPAMClient:
    def setup(self):
        client.remove_all_data()

    def test_get_empty_assignments(self):
        assert_equal(client.get_assigned_addresses(pool),
                     {})

    def test_add_assignment(self):
        none_assigned = client.get_assigned_addresses(pool)
        assert_equal(none_assigned, {})

        one_assigned = {"192.168.0.1": ""}
        assert_true(client.assign_address(pool, IPAddress("192.168.0.1")))
        assert_equal(client.get_assigned_addresses(pool), one_assigned)

        # Should not be able to add a duplicate.
        assert_false(client.assign_address(pool, IPAddress("192.168.0.1")))
        assert_equal(client.get_assigned_addresses(pool), one_assigned)

    def test_remove_assignment(self):
        address = IPAddress("192.168.0.1")
        assert_equal(client.get_assigned_addresses(pool), {})
        assert_true(client.assign_address(pool, address))
        assert_true(client.unassign_address(pool, address))
        assert_equal(client.get_assigned_addresses(pool), {})

    def test_remove_missing_assignment(self):
        address = IPAddress("192.168.0.1")
        assert_equal(client.get_assigned_addresses(pool), {})
        assert_false(client.unassign_address(pool, address))
        assert_equal(client.get_assigned_addresses(pool), {})

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

