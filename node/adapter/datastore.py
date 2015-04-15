from collections import namedtuple
import json
import etcd
from netaddr import IPNetwork, IPAddress, AddrFormatError
import os

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:4001"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

# etcd paths for Calico
CONFIG_PATH = "/calico/config/"
HOSTS_PATH = "/calico/host/"
HOST_PATH = HOSTS_PATH + "%(hostname)s/"
CONTAINER_PATH = HOST_PATH + "workload/docker/%(container_id)s/"
LOCAL_ENDPOINTS_PATH = HOST_PATH + "workload/docker/%(container_id)s/endpoint/"
ALL_ENDPOINTS_PATH = HOSTS_PATH  # Read all hosts
ENDPOINT_PATH = LOCAL_ENDPOINTS_PATH + "%(endpoint_id)s"
PROFILES_PATH = "/calico/policy/profile/"
PROFILE_PATH = PROFILES_PATH + "%(profile_id)s/"
TAGS_PATH = PROFILE_PATH + "tags"
RULES_PATH = PROFILE_PATH + "rules"
IP_POOL_PATH = "/calico/ipam/%(version)s/pool/"
BGP_PEER_PATH = "/calico/config/bgp_peer_rr_%(version)s/"

IF_PREFIX = "cali"
"""
prefix that appears in all Calico interface names in the root namespace. e.g.
cali123456789ab.
"""


class Rule(dict):
    """
    A Calico inbound or outbound traffic rule.
    """

    ALLOWED_KEYS = ["protocol",
                    "src_tag",
                    "src_ports",
                    "src_net",
                    "dst_tag",
                    "dst_ports",
                    "dst_net",
                    "icmp_type",
                    "action"]

    def __init__(self, **kwargs):
        super(Rule, self).__init__()
        for key, value in kwargs.iteritems():
            self[key] = value

    def __setitem__(self, key, value):
        if key not in Rule.ALLOWED_KEYS:
            raise KeyError("Key %s is not allowed on Rule." % key)

        # Convert any CIDR strings to netaddr before inserting them.
        if key in ("src_net", "dst_net"):
            value = IPNetwork(value)
        if key == "action" and value not in ("allow", "deny"):
            raise ValueError("'%s' is not allowed for key 'action'" % value)
        super(Rule, self).__setitem__(key, value)

    def to_json(self):

        # Convert IPNetworks to strings
        json_dict = self.copy()
        if "dst_net" in json_dict:
            json_dict["dst_net"] = str(json_dict["dst_net"])
        if "src_net" in json_dict:
            json_dict["src_net"] = str(json_dict["src_net"])
        return json.dumps(json_dict)

    def pprint(self):
        """Human readable description."""
        out = [self["action"]]
        if "protocol" in self:
            out.append(self["protocol"])
        if "icmp_type" in self:
            out.extend(["type", str(self["icmp_type"])])

        if "src_tag" in self or "src_ports" in self or "src_net" in self:
            out.append("from")
        if "src_tag" in self:
            out.extend(["tag", self["src_tag"]])
        elif "src_net" in self:
            out.append(str(self["src_net"]))
        if "src_ports" in self:
            out.extend(["ports", str(self["src_ports"])])

        if "dst_tag" in self or "dst_ports" in self or "dst_net" in self:
            out.append("to")
        if "dst_tag" in self:
            out.extend(["tag", self["dst_tag"]])
        elif "dst_net" in self:
            out.append(str(self["dst_net"]))
        if "dst_ports" in self:
            out.extend(["ports", str(self["dst_ports"])])

        return " ".join(out)


class Rules(namedtuple("Rules", ["id", "inbound_rules", "outbound_rules"])):
    """
    A set of Calico rules describing inbound and outbound network traffic
    policy.
    """

    def to_json(self):
        return json.dumps(self._asdict())

    @classmethod
    def from_json(cls, json_str):
        json_dict = json.loads(json_str)
        inbound_rules = []
        for rule in json_dict["inbound_rules"]:
            inbound_rules.append(Rule(**rule))
        outbound_rules = []
        for rule in json_dict["outbound_rules"]:
            outbound_rules.append(Rule(**rule))
        rules = cls(id=json_dict["id"],
                    inbound_rules=inbound_rules,
                    outbound_rules=outbound_rules)
        return rules


class Endpoint(object):

    def __init__(self, ep_id, state, mac):
        self.ep_id = ep_id
        self.state = state
        self.mac = mac

        self.profile_id = None
        self.ipv4_nets = set()
        self.ipv6_nets = set()
        self.ipv4_gateway = None
        self.ipv6_gateway = None

    def to_json(self):
        json_dict = {"state": self.state,
                     "name": IF_PREFIX + self.ep_id[:11],
                     "mac": self.mac,
                     "profile_id": self.profile_id,
                     "ipv4_nets": [str(net) for net in self.ipv4_nets],
                     "ipv6_nets": [str(net) for net in self.ipv6_nets],
                     "ipv4_gateway": str(self.ipv4_gateway) if
                                     self.ipv4_gateway else None,
                     "ipv6_gateway": str(self.ipv6_gateway) if
                                     self.ipv6_gateway else None}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, ep_id, json_str):
        json_dict = json.loads(json_str)
        ep = cls(ep_id=ep_id,
                 state=json_dict["state"],
                 mac=json_dict["mac"])
        for net in json_dict["ipv4_nets"]:
            ep.ipv4_nets.add(IPNetwork(net))
        for net in json_dict["ipv6_nets"]:
            ep.ipv6_nets.add(IPNetwork(net))
        ipv4_gw = json_dict["ipv4_gateway"]
        if ipv4_gw:
            ep.ipv4_gateway = IPAddress(ipv4_gw)
        ipv6_gw = json_dict["ipv6_gateway"]
        if ipv6_gw:
            ep.ipv6_gateway = IPAddress(ipv6_gw)
        ep.profile_id = json_dict["profile_id"]
        return ep


class Profile(object):
    """A Calico policy profile."""

    def __init__(self, name):
        self.name = name
        self.tags = set()

        # Default to empty lists of rules.
        self.rules = Rules(name, [], [])


class Vividict(dict):
    # From http://stackoverflow.com/a/19829714
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value


class DatastoreClient(object):
    """
    An datastore client that exposes high level Calico operations needed by the
    calico CLI.
    """

    def __init__(self):
        etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
        (host, port) = etcd_authority.split(":", 1)
        self.etcd_client = etcd.Client(host=host, port=int(port))

    def ensure_global_config(self):
        """
        Ensure the global config settings for Calico exist, creating them with
        defaults if they don't.
        :return: None.
        """
        config_dir = CONFIG_PATH
        try:
            self.etcd_client.read(config_dir)
        except KeyError:
            # Didn't exist, create it now.
            self.etcd_client.write(config_dir + "InterfacePrefix", IF_PREFIX)
            self.etcd_client.write(config_dir + "LogSeverityFile", "DEBUG")
            self.etcd_client.write(config_dir + "Ready", "true")

    def create_host(self, hostname, bird_ip, bird6_ip):
        """
        Create a new Calico host.

        :param hostname: The name of the host to create.
        :param bird_ip: The IP address BIRD should listen on.
        :param bird6_ip: The IP address BIRD6 should listen on.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        # Set up the host
        self.etcd_client.write(host_path + "bird_ip", bird_ip)
        self.etcd_client.write(host_path + "bird6_ip", bird6_ip)
        self.etcd_client.write(host_path + "config/marker", "created")
        workload_dir = host_path + "workload"
        try:
            self.etcd_client.read(workload_dir)
        except KeyError:
            # Didn't exist, create it now.
            self.etcd_client.write(workload_dir, None, dir=True)
        return

    def remove_host(self, hostname):
        """
        Remove a Calico host.
        :param hostname: The name of the host to remove.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        try:
            self.etcd_client.delete(host_path, dir=True, recursive=True)
        except KeyError:
            pass

    def get_ip_pools(self, version):
        """
        Get the configured IP pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of netaddr.IPNetwork IP pools.
        """
        assert version in ("v4", "v6")
        pool_path = IP_POOL_PATH % {"version": version}
        return map(IPNetwork, self._get_path_with_keys(pool_path).keys())

    def add_ip_pool(self, version, pool):
        """
        Add the given pool to the list of IP allocation pools.  If the pool
        already exists, this method completes silently without modifying the
        list of pools.

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

    def remove_ip_pool(self, version, pool):
        """
        Delete the given CIDR range from the list of pools.  If the pool does
        not exist, raise a KeyError.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        pool_path = IP_POOL_PATH % {"version": version}
        pools = self._get_path_with_keys(pool_path)
        try:
            key = pools[str(pool.cidr)]
            self.etcd_client.delete(key)
        except KeyError:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % pool)

    def get_bgp_peers(self, version):
        """
        Get the configured BGP Peers

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of netaddr.IPAddress IP addresses.
        """
        assert version in ("v4", "v6")
        bgp_peer_path = BGP_PEER_PATH % {"version": version}
        return map(IPAddress, self._get_path_with_keys(bgp_peer_path).keys())


    def _get_path_with_keys(self, path):
        """
        Retrieve all the keys in a path and create a reverse dict
        values -> keys

        :param path: The path to get the keys from.
        :return: dict of {<values>: <etcd key>}
        """

        try:
            nodes = self.etcd_client.read(path).children
        except KeyError:
            # Path doesn't exist.
            return {}
        else:
            values = {}
            for child in nodes:
                value = child.value
                if value:
                    values[value] = child.key
            return values

    def add_bgp_peer(self, version, ip):
        """
        Add a BGP Peer.
d
        If the peer already exists then do nothing.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param ip: The IP address to add. (an IPAddress)
        :return: Nothing
        """
        assert version in ("v4", "v6")
        assert isinstance(ip, IPAddress)
        bgp_peer_path = BGP_PEER_PATH % {"version": version}

        # Check if the peer exists.
        if ip in self.get_bgp_peers(version):
            return

        self.etcd_client.write(bgp_peer_path, str(ip), append=True)

    def remove_bgp_peer(self, version, ip):
        """
        Delete a BGP Peer

        :param version: "v4" for IPv4, "v6" for IPv6
        :param ip: The IP address to delete. (an IPAddress)
        :return: Nothing
        """
        assert version in ("v4", "v6")
        assert isinstance(ip, IPAddress)
        bgp_peer_path = BGP_PEER_PATH % {"version": version}

        peers = self._get_path_with_keys(bgp_peer_path)
        try:
            key = peers[str(ip)]
            self.etcd_client.delete(key)
        except KeyError:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured peer." % ip)

    def profile_exists(self, name):
        """
        Check if a profile exists.

        :param name: The name of the profile.
        :return: True if the profile exists, false otherwise.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            _ = self.etcd_client.read(profile_path)
        except KeyError:
            return False
        else:
            return True

    def create_profile(self, name):
        """
        Create a policy profile.  By default, containers in a profile
        accept traffic only from other containers in that profile, but can send
        traffic anywhere.

        Note this will clobber any existing profile with this name.

        :param name: Unique string name for the profile.
        :return: nothing.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        self.etcd_client.write(profile_path + "tags", '["%s"]' % name)

        # Accept inbound traffic from self, allow outbound traffic to anywhere.
        default_deny = Rule(action="deny")
        accept_self = Rule(action="allow", src_tag=name)
        default_allow = Rule(action="allow")
        rules = Rules(id=name,
                      inbound_rules=[accept_self, default_deny],
                      outbound_rules=[default_allow])
        self.etcd_client.write(profile_path + "rules", rules.to_json())

    def remove_profile(self, name):
        """
        Delete a policy profile with a given name.

        :param name: Unique string name for the profile.
        :return: the ID of the profile that was deleted, or None if the profile
        couldn't be found.
        """

        profile_path = PROFILE_PATH % {"profile_id": name}
        self.etcd_client.delete(profile_path, recursive=True, dir=True)
        return

    def get_profile_names(self):
        """
        Get the all configured profiles.
        :return: a set of profile names
        """
        profiles = set()
        try:
            etcd_profiles = self.etcd_client.read(PROFILES_PATH,
                                                  recursive=True).children
            for child in etcd_profiles:
                packed = child.key.split("/")
                if len(packed) > 4:
                    profiles.add(packed[4])
        except KeyError:
            # Means the PROFILES_PATH was not set up.  So, profile does not
            # exist.
            pass
        return profiles

    def get_profile(self, name):
        """
        Get a Profile object representing the named profile from the data
        store.

        :param name: The name of the profile.
        :return: A Profile object.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        # Note: raises KeyError if profile doesn't exist.
        _ = self.etcd_client.read(profile_path)
        profile = Profile(name)

        tags_path = TAGS_PATH % {"profile_id": name}
        try:
            tags_result = self.etcd_client.read(tags_path)
            tags = json.loads(tags_result.value)
            profile.tags = set(tags)
        except KeyError:
            pass

        rules_path = RULES_PATH % {"profile_id": name}
        try:
            rules_result = self.etcd_client.read(rules_path)
            rules = Rules.from_json(rules_result.value)
            profile.rules = rules
        except KeyError:
            pass

        return profile

    def get_profile_members(self, name):
        """
        Get all endpoint members of named profile.

        :param name: Unique string name of the profile.
        :return: a list of members
        """
        members = []
        try:
            endpoints = self.etcd_client.read(ALL_ENDPOINTS_PATH,
                                              recursive=True)
        except KeyError:
            # Means the ALL_ENDPOINTS_PATH was not set up.  So, profile has no
            # members because there are no endpoints.
            return members

        for child in endpoints.leaves:
            packed = child.key.split("/")
            if len(packed) == 9:
                ep_id = packed[-1]
                ep = Endpoint.from_json(ep_id, child.value)
                if ep.profile_id == name:
                    members.append(ep.ep_id)
        return members

    def profile_update_tags(self, profile):
        """
        Write the tags set on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with tags stored on it.
        :return: None
        """
        tags_path = TAGS_PATH % {"profile_id": profile.name}
        self.etcd_client.write(tags_path, json.dumps(list(profile.tags)))

    def profile_update_rules(self, profile):
        """
        Write the rules on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with rules stored on it.
        :return: None
        """
        rules_path = RULES_PATH % {"profile_id": profile.name}
        self.etcd_client.write(rules_path, profile.rules.to_json())

    def add_workload_to_profile(self, hostname, profile_name, container_id):
        """

        :param hostname: The host the workload is on.
        :param profile_name: The profile to add the workload to.
        :param container_id: The Docker container ID of the workload.
        :return: None.
        """
        endpoint_id = self.get_ep_id_from_cont(hostname, container_id)

        # Change the profile on the endpoint.
        ep = self.get_endpoint(hostname, container_id, endpoint_id)
        ep.profile_id = profile_name
        self.set_endpoint(hostname, container_id, ep)

    def remove_workload_from_profile(self, hostname, container_id):
        """

        :param hostname: The name of the host the container is on.
        :param container_id: The Docker container ID.
        :return: None.
        """
        endpoint_id = self.get_ep_id_from_cont(hostname, container_id)

        # Change the profile on the endpoint.
        ep = self.get_endpoint(hostname, container_id, endpoint_id)
        ep.profile_id = None
        self.set_endpoint(hostname, container_id, ep)

    def get_ep_id_from_cont(self, hostname, container_id):
        """
        Get a single endpoint ID from a container ID.

        :param hostname: The host the container is on.
        :param container_id: The Docker container ID.
        :return: Endpoint ID as a string.
        """
        ep_path = LOCAL_ENDPOINTS_PATH % {"hostname": hostname,
                                          "container_id": container_id}
        try:
            endpoints = self.etcd_client.read(ep_path).leaves
        except KeyError:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." %
                           container_id)

        # Get the first endpoint & ID
        try:
            endpoint = endpoints.next()
            (_, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 8)
            return endpoint_id
        except StopIteration:
            raise NoEndpointForContainer(
                "Container with ID %s has no endpoints." % container_id)

    def get_endpoint(self, hostname, container_id, endpoint_id):
        """
        Get all of the details for a single endpoint.

        :param hostname: The hostname that the endpoint lives on.
        :param container_id: The container that the endpoint belongs to.
        :param endpoint_id: The ID of the endpoint
        :return:  an Endpoint Object
        """
        ep_path = ENDPOINT_PATH % {"hostname": hostname,
                                   "container_id": container_id,
                                   "endpoint_id": endpoint_id}
        ep_json = self.etcd_client.read(ep_path).value
        ep = Endpoint.from_json(endpoint_id, ep_json)
        return ep

    def set_endpoint(self, hostname, container_id, endpoint):
        """
        Write a single endpoint object to the datastore.

        :param hostname: The hostname for the Docker hosting this container.
        :param container_id: The Docker container ID.
        :param endpoint: The Endpoint to add to the container.
        """
        ep_path = ENDPOINT_PATH % {"hostname": hostname,
                                   "container_id": container_id,
                                   "endpoint_id": endpoint.ep_id}
        self.etcd_client.write(ep_path, endpoint.to_json())

    def get_hosts(self):
        """
        Get the all configured hosts
        :return: a dict of hostname => {
                               type => {
                                   container_id => {
                                       endpoint_id => Endpoint
                                   }
                               }
                           }
        """
        hosts = Vividict()
        try:
            etcd_hosts = self.etcd_client.read(HOSTS_PATH,
                                               recursive=True).leaves
            for child in etcd_hosts:
                packed = child.key.split("/")
                if 9 > len(packed) > 4:
                    (_, _, _, host, _) = packed[0:5]
                    if not hosts[host]:
                        hosts[host] = Vividict()
                elif len(packed) == 9:
                    (_, _, _, host, _, container_type, container_id, _,
                     endpoint_id) = packed
                    ep = Endpoint.from_json(endpoint_id, child.value)
                    hosts[host][container_type][container_id][endpoint_id] = ep
        except KeyError:
            pass

        return hosts

    def get_default_next_hops(self, hostname):
        """
        Get the next hop IP addresses for default routes on the given host.

        :param hostname: The hostname for which to get default route next hops.
        :return: Dict of {ip_version: IPAddress}
        """

        host_path = HOST_PATH % {"hostname": hostname}
        ipv4 = self.etcd_client.read(host_path + "bird_ip").value
        ipv6 = self.etcd_client.read(host_path + "bird6_ip").value

        next_hops = {}

        # The IP addresses read from etcd could be blank. Only store them if
        # they can be parsed by IPAddress
        try:
            next_hops[4] = IPAddress(ipv4)
        except AddrFormatError:
            pass

        try:
            next_hops[6] = IPAddress(ipv6)
        except AddrFormatError:
            pass

        return next_hops

    def remove_all_data(self):
        """
        Remove all data from the datastore.

        We don't care if Calico data can't be found.

        """
        try:
            self.etcd_client.delete("/calico", recursive=True, dir=True)
        except KeyError:
            pass

    def remove_container(self, hostname, container_id):
        """
        Remove a container from the datastore.
        :param hostname: The name of the host the container is on.
        :param container_id: The Docker container ID.
        :return: None.
        """
        container_path = CONTAINER_PATH % {"hostname": hostname,
                                           "container_id": container_id}
        self.etcd_client.delete(container_path, recursive=True, dir=True)


class NoEndpointForContainer(Exception):
    """
    Tried to get the endpoint associated with a container that has no
    endpoints.
    """
    pass
