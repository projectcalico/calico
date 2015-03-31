from datastore import DatastoreClient


class RandomAssignment(object):
    """
    Assign IP addresses at random.
    """
    def allocate(pool, assigned):
        pass

class SequentialAssignment(object):
    """
    Assign IP addresses sequentially
    """

    def __init__(self):
        # Init an etcd client.
        self.etcd = DatastoreClient()

    def allocate(self, pool):
        """
        Attempt to allocate an IP address from the provided pool.

        :param pool: The pool to allocate from (an IPNetwork)
        :return: An IP address which has been allocated (a string) or None
        if allocation failed.
        """
        while True:
            already_assigned = self.etcd.get_assigned_addresses(pool)
            new_assignment = already_assigned.copy()

            assigned_address = self._get_next(pool, already_assigned)
            if assigned_address is None:
                # the pool is full, we can't allocate an address
                return None
            else:
                # We've found an address to try.
                # Attempt to write the address to the datastore.
                new_assignment[assigned_address] = ""

                if self.etcd.update_assigned_address(pool,
                                                     already_assigned,
                                                     new_assignment):
                    return assigned_address

    def _get_next(self, pool, assigned):
        """
        Gets the next address in a range.
        :param pool: The pool to allocate from (an IPNetwork)
        :return: the next IP address to try (a string), or None if the pool
                 is full.
        """
        for addr in pool.iter_hosts():
            addr_string = str(addr)
            if addr_string not in assigned:
                return addr_string
        return None