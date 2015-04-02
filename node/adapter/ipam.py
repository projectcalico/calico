from netaddr import IPAddress
from datastore import DatastoreClient

IP_ASSIGNMENT_PATH = "/calico/ipam/%(version)s/assignment/%(pool)s"
IP_ASSIGNMENT_KEY = IP_ASSIGNMENT_PATH + "/%(address)s"


class SequentialAssignment(object):
    """
    Assign IP addresses sequentially
    """

    def __init__(self):
        # Init an etcd client.
        self.etcd = IPAMClient()

    def allocate(self, pool):
        """
        Attempt to allocate an IP address from the provided pool.

        :param IPNetwork pool: The pool to allocate from
        :return: An IP address which has been allocated or None
        if allocation failed.
        :rtype str:
        """
        while True:
            assigned_addresses = self.etcd.get_assigned_addresses(pool)

            candidate_address = self._get_next(pool, assigned_addresses)
            if candidate_address is None:
                # the pool is full, we can't allocate an address
                return None
            else:
                # We've found an address to try.
                if self.etcd.assign_address(pool,
                                            IPAddress(candidate_address)):
                    return candidate_address

    def _get_next(self, pool, assigned):
        """
        Gets the next address in a range.
        :param IPNetwork pool: The pool to allocate from
        :param assigned: a dict of addresses that are already assigned.
        :return: the next IP address to try (a string), or None if the pool
                 is full.
        """
        for addr in pool.iter_hosts():
            addr_string = str(addr)
            if addr_string not in assigned:
                return addr_string
        return None


class IPAMClient(DatastoreClient):
    def assign_address(self, pool, address):
        """
        Attempt to assign an IPAddress in a pool.
        Fails if the address is already assigned.
        The directory for storing assignments in this pool must already exist.

        :param IPNetwork pool: The pool that the assignment is from.
        :param IPAddress address: The address to assign.

        :return: True if the allocation succeeds, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        key = IP_ASSIGNMENT_KEY % {"version": "v%s" % pool.version,
                                   "pool": str(pool).replace("/", "-"),
                                   "address": address}
        try:
            self.etcd_client.write(key, "", prevExist=False)
        except KeyError:
            return False
        else:
            return True

    def unassign_address(self, pool, address):
        """
        Unassign an IP from a pool.

        :param IPNetwork pool: The pool that the assignment is from.
        :param IPAddress address: The address to unassign.

        :return: True if the address was unassigned, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        key = IP_ASSIGNMENT_KEY % {"version": "v%s" % pool.version,
                                   "pool": str(pool).replace("/", "-"),
                                   "address": address}
        try:
            self.etcd_client.delete(key)
        except KeyError:
            return False
        else:
            return True

    def get_assigned_addresses(self, pool):
        """
        :param IPNetwork pool: The pool to get assignments for.
        :return: The assigned addresses from the pool
        :rtype dict of [str, str]
        """
        directory = IP_ASSIGNMENT_PATH % {"version": "v%s" % pool.version,
                                          "pool": str(pool).replace("/", "-")}
        try:
            nodes = self.etcd_client.read(directory).children
        except KeyError:
            # Path doesn't exist so configure now.
            self.etcd_client.write(directory, None, dir=True)
            return {}
        else:
            addresses = {}
            for child in nodes:
                if not child.dir:
                    addresses[child.key.split("/")[-1]] = ""
            return addresses