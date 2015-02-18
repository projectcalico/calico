from collections import namedtuple
import json
import socket
import etcd #TODO - rename this
from netaddr import IPNetwork
import os

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:4001"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

# etcd paths for Calico
HOST_PATH = "/calico/host/%(hostname)s/"
MASTER_PATH = "/calico/master"
MASTER_IP_PATH = "/calico/master/ip"
GROUPS_PATH = "/calico/network/group/"
GROUP_PATH = "/calico/network/group/%(group_id)s/"
GROUP_MEMBER_PATH = "/calico/network/group/%(group_id)s/member"
CONTAINER_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/"
ENDPOINTS_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/endpoint/"
IP_POOL_PATH = "/calico/ipam/%(version)s/pool/"
IP_POOLS_PATH = "/calico/ipam/%(version)s/pool/"
ENDPOINT_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/" + \
                "endpoint/%(endpoint_id)s/"

hostname = socket.gethostname()


class Rule(namedtuple("Rule", ["group", "cidr", "protocol", "port"])):
    """
    A Calico inbound or outbound traffic rule.
    """

    def to_json(self):
        return json.dumps(self._asdict())


class Vividict(dict):
    # From http://stackoverflow.com/a/19829714
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value


class DatastoreClient(object):
    """
    An datastore client that exposes high level Calico operations needed by the calico CLI.
    """

    def __init__(self):
        etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
        (host, port) = etcd_authority.split(":", 1)
        self.etcd_client = etcd.Client(host=host, port=int(port))

    def create_host(self, bird_ip):
        """
        Create a new Calico host.

        :param bird_ip: The IP address BIRD should listen on.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        # Set up the host
        self.etcd_client.write(host_path + "bird_ip", bird_ip)
        workload_dir = host_path + "workload"
        try:
            self.etcd_client.read(workload_dir)
        except KeyError:
            # Didn't exist, create it now.
            self.etcd_client.write(workload_dir, None, dir=True)
        return

    def remove_host(self):
        """
        Remove a Calico host.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        try:
            self.etcd_client.delete(host_path, dir=True, recursive=True)
        except KeyError:
            pass

    def set_master(self, ip):
        """
        Record the IP address of the Calico Master.
        :param ip: The IP address to reach Calico Master.
        :return: nothing.
        """
        # update the master IP
        self.etcd_client.write(MASTER_IP_PATH, ip)

    def remove_master(self):
        """
        Record the IP address of the Calico Master.
        :return: nothing.
        """
        try:
            self.etcd_client.delete(MASTER_PATH)
        except KeyError:
            pass

    def get_master(self):
        """
        Get the IP address of the Calico Master
        :return: The IP address to reach Calico Master or None if it can't be found.
        """
        try:
            return self.etcd_client.get(MASTER_IP_PATH).value
        except KeyError:
            return None

    def get_groups_by_endpoint(self, endpoint_id):
        return []   # TODO

    def get_ip_pools(self, version):
        """
        Get the configured IP pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of netaddr.IPNetwork IP pools.
        """
        assert version in ("v4", "v6")
        return self._get_ip_pools_with_keys(version).keys()

    def _get_ip_pools_with_keys(self, version):
        """
        Get configured IP pools with their etcd keys.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: dict of {<IPNetwork>: <etcd key>} for the pools.
        """
        pool_path = IP_POOLS_PATH % {"version": version}
        try:
            nodes = self.etcd_client.read(pool_path).children
        except KeyError:
            # Path doesn't exist.  Interpret as no configured pools.
            return {}
        else:
            pools = {}
            for child in nodes:
                cidr = child.value
                pool = IPNetwork(cidr)
                pools[pool] = child.key
            return pools

    def add_ip_pool(self, version, pool):
        """
        Add the given pool to the list of IP allocation pools.  If the pool already exists, this
        method completes silently without modifying the list of pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        pool = pool.cidr

        # Check if the pool exists.
        if pool in self.get_ip_pools(version):
            return

        pool_path = IP_POOL_PATH % {"version": version}
        self.etcd_client.write(pool_path, str(pool), append=True)

    def del_ip_pool(self, version, pool):
        """
        Delete the given CIDR range from the list of pools.  If the pool does not exist, raise a
        KeyError.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        pools = self._get_ip_pools_with_keys(version)
        try:
            key = pools[pool.cidr]
            self.etcd_client.delete(key)
        except KeyError:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % pool)

    def create_group(self, group_id, name):
        """
        Create a security group.  In this implementation, security groups accept traffic only from
        themselves, but can send traffic anywhere.

        :param group_id: Group UUID (string)
        :param name: Human readable name for the group.
        :return: nothing.
        """

        # Create the group directory.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.write(group_path + "name", name)

        # Default rule
        self.etcd_client.write(group_path + "rule/inbound_default", "deny")
        self.etcd_client.write(group_path + "rule/outbound_default", "deny")

        # Allow traffic inbound from group.
        allow_group = Rule(group=group_id, cidr=None, protocol=None, port=None)
        self.etcd_client.write(group_path + "rule/inbound/1", allow_group.to_json())

        # Allow traffic outbound to group and any address.
        allow_any_ip = Rule(group=None, cidr="0.0.0.0/0", protocol=None, port=None)
        self.etcd_client.write(group_path + "rule/outbound/1", allow_group.to_json())
        self.etcd_client.write(group_path + "rule/outbound/2", allow_any_ip.to_json())

    def delete_group(self, name):
        """
        Delete a security group with a given name. If there are multiple groups with that name
        it will just delete one of them.

        :param name: Human readable name for the group.
        :return: the ID of the group that was deleted, or None if the group couldn't be found.
        """

        # Find a group ID
        group_id = self.get_group_id(name)
        if group_id:
            group_path = GROUP_PATH % {"group_id": group_id}
            self.etcd_client.delete(group_path, recursive=True, dir=True)
        return group_id

    def get_group_id(self, name_to_find):
        """
        Get the UUID of the named group.  If multiple groups have the same name, the first matching
        one will be returned.
        :param name_to_find:
        :return: string UUID for the group, or None if the name was not found.
        """
        for group_id, name in self.get_groups().iteritems():
            if name_to_find == name:
                return group_id
        return None

    def get_groups(self):
        """
        Get the all configured groups.
        :return: a dict of group_id => name
        """
        groups = {}
        try:
            etcd_groups = self.etcd_client.read(GROUPS_PATH, recursive=True,).leaves
            for child in etcd_groups:
                (_, _, _, _, group_id, final_key) = child.key.split("/", 5)
                if final_key == "name":
                    groups[group_id] = child.value
        except KeyError:
            # Means the GROUPS_PATH was not set up.  So, group does not exist.
            pass
        return groups

    def get_group_members(self, group_id):
        """
        Get the all configured groups.
        :return: a list of members
        """
        members = []
        try:
            etcd_members = self.etcd_client.read(GROUP_MEMBER_PATH % {"group_id": group_id},
                                                 recursive=True).leaves
            for child in etcd_members:
                final_key = child.key.split("/")[-1]
                if final_key != "member":
                    members.append(final_key)
        except KeyError:
            # Means the GROUPS_MEMBER_PATH was not set up.  So, group does not exist.
            pass
        return members

    def add_endpoint_to_group(self, group_id, endpoint_id):
        # Add the endpoint to the group.  ./member/ is a keyset of endpoint IDs, so write empty
        # string as the value.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.write(group_path + "member/" + endpoint_id, "")

    def remove_endpoint_from_group(self, group_id, endpoint_id):
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.delete(group_path + "member/" + endpoint_id)

    def get_ep_id_from_cont(self, container_id):
        """
        Get a single endpoint ID from a container ID.

        :param container_id: The Docker container ID.
        :return: Endpoint ID as a string.
        """
        ep_path = ENDPOINTS_PATH % {"hostname": hostname,
                                    "container_id": container_id}
        try:
            endpoints = self.etcd_client.read(ep_path).leaves
        except KeyError:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." % container_id)

        # Get the first endpoint & ID
        endpoint = endpoints.next()
        (_, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 8)
        return endpoint_id

    def create_container(self, hostname, container_id, endpoint):
        """
        Set up a container in the /calico/ namespace on this host.  This function assumes 1
        container, with 1 endpoint.

        :param hostname: The hostname for the Docker hosting this container.
        :param container_id: The Docker container ID.
        :param endpoint: The Endpoint to add to the container.
        :return: Nothing
        """

        endpoint_path = ENDPOINT_PATH % {"hostname": hostname,
                                         "container_id": container_id,
                                         "endpoint_id": endpoint.id}
        self.etcd_client.write(endpoint_path + "addrs", json.dumps(endpoint.addrs))
        self.etcd_client.write(endpoint_path + "mac", endpoint.mac)
        self.etcd_client.write(endpoint_path + "state", endpoint.state)

    def get_hosts(self):
        """
        Get the all configured hosts
        :return: a dict of hostname => {type => {endpoint_id => {"addrs" => addr, "mac" => mac,
        "state" => state}}}
        """
        hosts = Vividict()
        try:
            etcd_hosts = self.etcd_client.read('/calico/host', recursive=True).leaves
            for child in etcd_hosts:
                packed = child.key.split("/")
                if len(packed) == 5:
                    (_, _, _, host, _) = packed
                    hosts[host] = Vividict()
                elif len(packed) == 10:
                    (_, _, _, host, _, container_type, container_id, _, endpoint_id, final_key) = \
                        packed
                    hosts[host][container_type][container_id][endpoint_id][final_key] = child.value
                else:
                    raise Exception("Unrecognized data")
        except KeyError:
            pass

        return hosts

    def remove_all_data(self):
        """
        Remove all data from the datastore.

        We don't care if Calico data can't be found.

        """
        try:
            self.etcd_client.delete("/calico", recursive=True, dir=True)
        except KeyError:
            pass

    def remove_container(self, container_id):
        container_path = CONTAINER_PATH % {"hostname": hostname,
                                           "container_id": container_id}
        self.etcd_client.delete(container_path)
