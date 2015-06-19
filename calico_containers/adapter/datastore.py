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

from collections import namedtuple
import copy
import json
import os
import re

import etcd
from etcd import EtcdKeyNotFound, EtcdException
from netaddr import IPNetwork, IPAddress, AddrFormatError

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:4001"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

# etcd paths for Calico
# TODO: modify string constants to accept orchestrator_id, replacing "docker" hardcoding.
# Any method that uses CONTAINER_PATH, LOCAL_ENDPOINTS_PATH, or ENDPOINT_PATH
# will need to be refactored to include orchestrator_id as a passed in parameters.
CALICO_V_PATH = "/calico/v1"
CONFIG_PATH = CALICO_V_PATH + "/config/"
HOSTS_PATH = CALICO_V_PATH + "/host/"
HOST_PATH = HOSTS_PATH + "%(hostname)s/"
CONTAINER_PATH = HOST_PATH + "workload/docker/%(container_id)s/"
LOCAL_ENDPOINTS_PATH = HOST_PATH + "workload/docker/%(container_id)s/endpoint/"
ALL_ENDPOINTS_PATH = HOSTS_PATH  # Read all hosts
ENDPOINT_PATH = LOCAL_ENDPOINTS_PATH + "%(endpoint_id)s"
PROFILES_PATH = CALICO_V_PATH + "/policy/profile/"
PROFILE_PATH = PROFILES_PATH + "%(profile_id)s/"
TAGS_PATH = PROFILE_PATH + "tags"
RULES_PATH = PROFILE_PATH + "rules"
IP_POOL_PATH = CALICO_V_PATH + "/ipam/%(version)s/pool"
IP_POOL_KEY = IP_POOL_PATH + "/%(pool)s"
BGP_PEERS_PATH = CALICO_V_PATH + "/config/bgp_peer_%(version)s/"
BGP_PEER_PATH = CALICO_V_PATH + "/config/bgp_peer_%(version)s/%(peer_ip)s"
BGP_NODE_DEF_AS_PATH = CONFIG_PATH + "bgp_as"
BGP_NODE_MESH_PATH = CONFIG_PATH + "bgp_node_mesh"
HOST_BGP_PEERS_PATH = HOST_PATH + "bgp_peer_%(version)s/"
HOST_BGP_PEER_PATH = HOST_PATH + "bgp_peer_%(version)s/%(peer_ip)s"

# Paths used in endpoint enumeration depending on available parameters.
ALL_ENDP_PATH = HOSTS_PATH
HOST_ENDP_PATH = HOST_PATH
ORCHESTRATOR_ENDP_PATH = HOST_ENDP_PATH + "workload/%(orchestrator_id)s/"
WORKLOAD_ENDP_PATH = ORCHESTRATOR_ENDP_PATH + "%(workload_id)s/endpoint/"
ENDPOINT_ENDP_PATH = WORKLOAD_ENDP_PATH + "%(endpoint_id)s"

# Endpoint path match regex
ENDPOINT_KEY_MATCH = re.compile("/calico/v1/host/(?P<hostname>[^/]*)/"
                                "workload/(?P<orchestrator_id>[^/]*)/"
                                "(?P<workload_id>[^/]*)/"
                                "endpoint/(?P<endpoint_id>[^/]*)")

IF_PREFIX = "cali"
"""
prefix that appears in all Calico interface names in the root namespace. e.g.
cali123456789ab.
"""

VETH_NAME = "eth1"
"""The name to give to the veth in the target container's namespace. Default
to eth1 because eth0 could be in use"""

# The default node AS number
DEFAULT_AS_NUM = 64511


def handle_errors(fn):
    """
    Decorator function to decorate Datastore API methods to handle common
    exception types and re-raise as datastore specific errors.
    :param fn: The function to decorate.
    :return: The decorated function.
    """
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except EtcdException as e:
            # Don't leak out etcd exceptions.
            raise DataStoreError("%s: Error accessing etcd (%s).  Is etcd "
                                 "running?" % (fn.__name__, e.message))
    return wrapped


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
                    "icmp_code",
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
        """
        Convert the Rule object to a JSON string.

        :return:  A JSON string representation of this object.
        """
        return json.dumps(self.to_json_dict())

    def to_json_dict(self):
        """
        Convert the Rule object to a dict that can be directly converted to
        JSON.

        :return: A dict containing valid JSON types.
        """
        # Convert IPNetworks to strings
        json_dict = self.copy()
        if "dst_net" in json_dict:
            json_dict["dst_net"] = str(json_dict["dst_net"])
        if "src_net" in json_dict:
            json_dict["src_net"] = str(json_dict["src_net"])
        return json_dict

    def pprint(self):
        """Human readable description."""
        out = [self["action"]]
        if "protocol" in self:
            out.append(self["protocol"])
        if "icmp_type" in self:
            out.extend(["type", str(self["icmp_type"])])
        if "icmp_code" in self:
            out.extend(["code", str(self["icmp_code"])])

        if "src_tag" in self or "src_ports" in self or "src_net" in self:
            out.append("from")
        if "src_ports" in self:
            ports = ",".join(str(p) for p in self["src_ports"])
            out.extend(["ports", ports])
        if "src_tag" in self:
            out.extend(["tag", self["src_tag"]])
        if "src_net" in self:
            out.append(str(self["src_net"]))

        if "dst_tag" in self or "dst_ports" in self or "dst_net" in self:
            out.append("to")
        if "dst_ports" in self:
            ports = ",".join(str(p) for p in self["dst_ports"])
            out.extend(["ports", ports])
        if "dst_tag" in self:
            out.extend(["tag", self["dst_tag"]])
        if "dst_net" in self:
            out.append(str(self["dst_net"]))

        return " ".join(out)


class Rules(namedtuple("Rules", ["id", "inbound_rules", "outbound_rules"])):
    """
    A set of Calico rules describing inbound and outbound network traffic
    policy.
    """

    def to_json(self):
        """
        Convert the Rules object to a JSON string.

        :return:  A JSON string representation of this object.
        """
        json_dict = self._asdict()
        rules = json_dict["inbound_rules"]
        json_dict["inbound_rules"] = [rule.to_json_dict() for rule in rules]
        rules = json_dict["outbound_rules"]
        json_dict["outbound_rules"] = [rule.to_json_dict() for rule in rules]
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, json_str):
        """
        Create a Rules object from a JSON string.

        :param json_str: A JSON string representation of a Rules object.
        :return: A Rules object.
        """
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


class BGPPeer(object):
    """
    Class encapsulating a BGPPeer.
    """

    def __init__(self, ip, as_num):
        """
        Constructor.
        :param ip: The BGPPeer IP address (string or IPAddress)
        :param as_num: The AS Number (string or int)
        """
        self.ip = IPAddress(ip)
        self.as_num = int(as_num)

    def to_json(self):
        """
        Convert the BGPPeer to a JSON string.
        :return: A JSON string.
        """
        json_dict = {"ip": str(self.ip), "as_num": self.as_num}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, json_str):
        """
        Convert the json string into a BGPPeer object.
        :param json_str: The JSON string representing a BGPPeer.
        :return: A BGPPeer object.
        """
        json_dict = json.loads(json_str)
        return cls(json_dict["ip"], json_dict["as_num"])

    def __eq__(self, other):
        if not isinstance(other, BGPPeer):
            return NotImplemented
        return (self.ip == other.ip and
                self.as_num == other.as_num)


class Endpoint(object):
    """
    Class encapsulating an Endpoint.

    This class keeps track of the original JSON representation of the
    endpoint to allow atomic updates to be performed.
    """

    def __init__(self, hostname, orchestrator_id, workload_id, endpoint_id,
                 state, mac):
        self.hostname = hostname
        self.orchestrator_id = orchestrator_id
        self.workload_id = workload_id
        self.endpoint_id = endpoint_id
        self.state = state
        self.mac = mac

        self.ipv4_nets = set()
        self.ipv6_nets = set()
        self.ipv4_gateway = None
        self.ipv6_gateway = None

        self.if_name = None
        self.profile_ids = []
        self._original_json = None

    def to_json(self):
        json_dict = {"state": self.state,
                     "name": IF_PREFIX + self.endpoint_id[:11],
                     "mac": self.mac,
                     "container:if_name": self.if_name,
                     "profile_ids": self.profile_ids,
                     "ipv4_nets": sorted([str(net) for net in self.ipv4_nets]),
                     "ipv6_nets": sorted([str(net) for net in self.ipv6_nets]),
                     "ipv4_gateway": str(self.ipv4_gateway) if
                                     self.ipv4_gateway else None,
                     "ipv6_gateway": str(self.ipv6_gateway) if
                                     self.ipv6_gateway else None}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, endpoint_key, json_str):
        """
        Create an Endpoint from the endpoint raw JSON and the endpoint key.

        :param endpoint_key: The endpoint key (the etcd path to the endpoint)
        :param json_str: The raw endpoint JSON data.
        :return: An Endpoint object, or None if the endpoint_key does not
        represent and Endpoint.
        """
        match = ENDPOINT_KEY_MATCH.match(endpoint_key)
        if not match:
            return None

        hostname = match.group("hostname")
        orchestrator_id = match.group("orchestrator_id")
        workload_id = match.group("workload_id")
        endpoint_id = match.group("endpoint_id")

        json_dict = json.loads(json_str)
        ep = cls(hostname, orchestrator_id, workload_id, endpoint_id,
                 json_dict["state"], json_dict["mac"])

        for net in json_dict["ipv4_nets"]:
            ep.ipv4_nets.add(IPNetwork(net))
        for net in json_dict["ipv6_nets"]:
            ep.ipv6_nets.add(IPNetwork(net))
        ipv4_gw = json_dict.get("ipv4_gateway")
        if ipv4_gw:
            ep.ipv4_gateway = IPAddress(ipv4_gw)
        ipv6_gw = json_dict.get("ipv6_gateway")
        if ipv6_gw:
            ep.ipv6_gateway = IPAddress(ipv6_gw)

        # Version controlled fields
        profile_id = json_dict.get("profile_id", None)
        ep.profile_ids = [profile_id] if profile_id else \
                         json_dict.get("profile_ids", [])
        ep.if_name = json_dict.get("container:if_name", VETH_NAME)

        # Store the original JSON representation of this Endpoint.
        ep._original_json = json_str

        return ep

    def matches(self, hostname=None, orchestrator_id=None,
                workload_id=None, endpoint_id=None):
        """
        A less strict 'equals' function, which compares provided parameters to
        the current endpoint object.

        :return: True if the provided parameters match the Endpoint's
        parameters, False if any of the provided parameters are different from
        the Endpoint's parameters.
        """
        if hostname and hostname != self.hostname:
            return False
        elif orchestrator_id and orchestrator_id != self.orchestrator_id:
            return False
        elif workload_id and workload_id != self.workload_id:
            return False
        elif endpoint_id and endpoint_id != self.endpoint_id:
            return False
        else:
            return True

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return NotImplemented
        return (self.endpoint_id == other.endpoint_id and
                self.state == other.state and
                self.if_name == other.if_name and
                self.mac == other.mac and
                self.profile_ids == other.profile_ids and
                self.ipv4_nets == other.ipv4_nets and
                self.ipv6_nets == other.ipv6_nets and
                self.ipv4_gateway == other.ipv4_gateway and
                self.ipv6_gateway == other.ipv6_gateway)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def copy(self):
        return copy.deepcopy(self)


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

    @handle_errors
    def ensure_global_config(self):
        """
        Ensure the global config settings for Calico exist, creating them with
        defaults if they don't.
        :return: None.
        """
        config_dir = CONFIG_PATH
        try:
            self.etcd_client.read(config_dir)
        except EtcdKeyNotFound:
            # Didn't exist, create it now.
            self.etcd_client.write(config_dir + "InterfacePrefix", IF_PREFIX)

        # We are always ready
        self.etcd_client.write(CALICO_V_PATH + "/Ready", "true")

    @handle_errors
    def create_host(self, hostname, bird_ip, bird6_ip, as_num):
        """
        Create a new Calico host.

        :param hostname: The name of the host to create.
        :param bird_ip: The IP address BIRD should listen on.
        :param bird6_ip: The IP address BIRD6 should listen on.
        :param as_num: Optional AS Number to use for this host.  If not
        specified, the configured global or default global value is used.
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
        except EtcdKeyNotFound:
            # Didn't exist, create it now.
            self.etcd_client.write(workload_dir, None, dir=True)

        # Set or delete the node specific BGP AS number as required.  If the
        # value is missing from the etcd datastore, the BIRD templates will
        # inherit the configured global default value (and then the
        # hardcoded default value).
        if as_num is None:
            try:
                self.etcd_client.delete(host_path + "bgp_as")
            except EtcdKeyNotFound:
                pass
        else:
            self.etcd_client.write(host_path + "bgp_as", as_num)

        return

    @handle_errors
    def remove_host(self, hostname):
        """
        Remove a Calico host.
        :param hostname: The name of the host to remove.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        try:
            self.etcd_client.delete(host_path, dir=True, recursive=True)
        except EtcdKeyNotFound:
            pass

    @handle_errors
    def get_ip_pools(self, version):
        """
        Get the configured IP pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of netaddr.IPNetwork IP pools.
        """
        assert version in ("v4", "v6")
        pool_path = IP_POOL_PATH % {"version": version}
        try:
            keys = self.etcd_client.read(pool_path).children
        except EtcdKeyNotFound:
            # Path doesn't exist.
            pools = []
        else:
            # Path exists so convert directory names to CIDRs.  Note that
            # the children function is bugged when the directory is entry as
            # it contains a single entry equal to the directory path, so we
            # must filter this out.
            pools = [x.key.split("/")[-1].replace("-", "/")
                       for x in keys if x.key != pool_path]

        return map(IPNetwork, pools)

    @handle_errors
    def get_ip_pool_config(self, version, pool):
        """
        Get the configuration for the given pool.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: Dictionary of pool configuration
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        pool = pool.cidr

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(pool).replace("/", "-")}

        try:
            data = json.loads(self.etcd_client.read(key).value)
        except (KeyError, EtcdKeyNotFound):
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % pool)

        return data

    @handle_errors
    def add_ip_pool(self, version, pool, ipip=False, masquerade=False):
        """
        Add the given pool to the list of IP allocation pools.  If the pool
        already exists, this method completes silently without modifying the
        list of pools, other than possibly updating the ipip config.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :param ipip: Use IP-IP for pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        pool = pool.cidr

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(pool).replace("/", "-")}

        data = {"cidr" : str(pool)}
        if ipip:
            data["ipip"] = "tunl0"
        if masquerade:
            data["masquerade"] = True

        self.etcd_client.write(key, json.dumps(data))

    @handle_errors
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

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        pool = pool.cidr

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(pool).replace("/", "-")}
        try:
            self.etcd_client.delete(key)
        except (KeyError, EtcdKeyNotFound):
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % pool)

    @handle_errors
    def get_bgp_peers(self, version, hostname=None):
        """
        Get the configured BGP Peers.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param hostname: Optional hostname.  If supplied, this returns the
        node-specific BGP peers.  If None, this returns the globally configured
        BGP peers.
        :return: List of BGPPeer.
        """
        assert version in ("v4", "v6")
        if hostname is None:
            bgp_peers_path = BGP_PEERS_PATH % {"version": version}
        else:
            bgp_peers_path = HOST_BGP_PEERS_PATH % {"hostname": hostname,
                                                    "version": version}

        try:
            nodes = self.etcd_client.read(bgp_peers_path).children
        except EtcdKeyNotFound:
            # Path doesn't exist.
            return []

        # If there are no children etcd returns a single value with the parent
        # key and no value (so skip empty values).
        peers = [BGPPeer.from_json(node.value) for node in nodes if node.value]
        return peers

    @handle_errors
    def add_bgp_peer(self, version, bgp_peer, hostname=None):
        """
        Add a BGP Peer.

        If a peer exists with the peer IP address, this will update the peer .
        configuration.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param bgp_peer: The BGPPeer to add or update.
        :param hostname: Optional hostname.  If supplied, this stores the BGP
         peer in the node specific configuration.  If None, this stores the BGP
         peer as a globally configured peer.
        :return: Nothing
        """
        assert version in ("v4", "v6")
        if hostname is None:
            bgp_peer_path = BGP_PEER_PATH % {"version": version,
                                             "peer_ip": str(bgp_peer.ip)}
        else:
            bgp_peer_path = HOST_BGP_PEER_PATH % {"hostname": hostname,
                                                  "version": version,
                                                  "peer_ip": str(bgp_peer.ip)}
        self.etcd_client.write(bgp_peer_path, bgp_peer.to_json())

    @handle_errors
    def remove_bgp_peer(self, version, ip, hostname=None):
        """
        Delete a BGP Peer with the specified IP address.

        Raises KeyError if the Peer does not exist.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param ip: The IP address of the BGP peer to delete. (an IPAddress)
        :param hostname: Optional hostname.  If supplied, this stores the BGP
         peer in the node specific configuration.  If None, this stores the BGP
         peer as a globally configured peer.
        :return: Nothing
        """
        assert version in ("v4", "v6")
        assert isinstance(ip, IPAddress)
        if hostname is None:
            bgp_peer_path = BGP_PEER_PATH % {"version": version,
                                             "peer_ip": str(ip)}
        else:
            bgp_peer_path = HOST_BGP_PEER_PATH % {"hostname": hostname,
                                                  "version": version,
                                                  "peer_ip": str(ip)}
        try:
            self.etcd_client.delete(bgp_peer_path)
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured peer." % ip)

    @handle_errors
    def profile_exists(self, name):
        """
        Check if a profile exists.

        :param name: The name of the profile.
        :return: True if the profile exists, false otherwise.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            _ = self.etcd_client.read(profile_path)
        except EtcdKeyNotFound:
            return False
        else:
            return True

    @handle_errors
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
        # Note: We do not need to add a default_deny to outbound packet traffic
        # since Felix implements a default drop at the end if no profile has
        # accepted. Dropping the packet will kill it before it can potentially
        # be accepted by another profile on the container.
        accept_self = Rule(action="allow", src_tag=name)
        default_allow = Rule(action="allow")
        rules = Rules(id=name,
                      inbound_rules=[accept_self],
                      outbound_rules=[default_allow])
        self.etcd_client.write(profile_path + "rules", rules.to_json())

    @handle_errors
    def remove_profile(self, name):
        """
        Delete a policy profile with a given name.

        :param name: Unique string name for the profile.
        :return: nothing.
        """

        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            self.etcd_client.delete(profile_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured profile." % name)

    @handle_errors
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
                if len(packed) > 5:
                    profiles.add(packed[5])
        except EtcdKeyNotFound:
            # Means the PROFILES_PATH was not set up.  So, profile does not
            # exist.
            pass
        return profiles

    @handle_errors
    def get_profile(self, name):
        """
        Get a Profile object representing the named profile from the data
        store.

        :param name: The name of the profile.
        :return: A Profile object.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            _ = self.etcd_client.read(profile_path)
            profile = Profile(name)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured profile." % name)

        tags_path = TAGS_PATH % {"profile_id": name}
        try:
            tags_result = self.etcd_client.read(tags_path)
            tags = json.loads(tags_result.value)
            profile.tags = set(tags)
        except EtcdKeyNotFound:
            pass

        rules_path = RULES_PATH % {"profile_id": name}
        try:
            rules_result = self.etcd_client.read(rules_path)
            rules = Rules.from_json(rules_result.value)
            profile.rules = rules
        except EtcdKeyNotFound:
            pass

        return profile

    @handle_errors
    def get_profile_members_endpoint_ids(self, name):
        """
        Get all endpoint IDs that are members of named profile.

        :param name: Unique string name of the profile.
        :return: a list of members
        """
        members = []
        try:
            endpoints = self.etcd_client.read(ALL_ENDPOINTS_PATH,
                                              recursive=True)
        except EtcdKeyNotFound:
            # Means the ALL_ENDPOINTS_PATH was not set up.  So, profile has no
            # members because there are no endpoints.
            return members

        for child in endpoints.leaves:
            ep = Endpoint.from_json(child.key, child.value)
            if ep and name in ep.profile_ids:
                members.append(ep.endpoint_id)
        return members

    @handle_errors
    def get_profile_members(self, profile_name):
        """
        Get the all of the endpoint members of a profile.

        :param profile_name: Unique string name of the profile.
        :return: a dict of hostname => {
                               type => {
                                   container_id => {
                                       endpoint_id => Endpoint
                                   }
                               }
                           }
        """
        eps = Vividict()
        try:
            endpoints = self.etcd_client.read(ALL_ENDPOINTS_PATH,
                                              recursive=True).leaves
            for child in endpoints:
                ep = Endpoint.from_json(child.key, child.value)
                if ep and profile_name in ep.profile_ids:
                    eps[ep.hostname][ep.orchestrator_id][ep.workload_id][ep.endpoint_id] = ep
        except EtcdKeyNotFound:
            pass

        return eps

    @handle_errors
    def profile_update_tags(self, profile):
        """
        Write the tags set on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with tags stored on it.
        :return: None
        """
        tags_path = TAGS_PATH % {"profile_id": profile.name}
        self.etcd_client.write(tags_path, json.dumps(list(profile.tags)))

    @handle_errors
    def profile_update_rules(self, profile):
        """
        Write the rules on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with rules stored on it.
        :return: None
        """
        rules_path = RULES_PATH % {"profile_id": profile.name}
        self.etcd_client.write(rules_path, profile.rules.to_json())

    @handle_errors
    def append_profiles_to_endpoint(self, profile_names, **kwargs):
        """
        Append a list of profiles to the endpoint.  This assumes there is a
        single endpoint per container.

        Raises ProfileAlreadyInEndpoint if any of the profiles are already
        configured in the endpoint profile list.

        :param hostname: The host the workload is on.
        :param profile_names: The profiles to append to the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Change the profiles on the endpoint.  Check that we are not adding a
        # duplicate entry, and perform an update to ensure atomicity.
        ep = self.get_endpoint(**kwargs)
        for profile_name in ep.profile_ids:
            if profile_name in profile_names:
                raise ProfileAlreadyInEndpoint(profile_name)
        ep.profile_ids += profile_names
        self.update_endpoint(ep)

    @handle_errors
    def set_profiles_on_endpoint(self, profile_names, **kwargs):
        """
        Set a list of profiles on the endpoint.  This assumes there is a single
        endpoint per container.

        :param hostname: The host the workload is on.
        :param profile_names: The profiles to set for the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Set the profiles on the endpoint.
        ep = self.get_endpoint(**kwargs)
        ep.profile_ids = profile_names
        self.update_endpoint(ep)

    @handle_errors
    def remove_profiles_from_endpoint(self, profile_names, **kwargs):
        """
        Remove a profiles from the endpoint profile list.  This assumes there
        is a single endpoint per container.

        Raises ProfileNotInEndpoint if any of the profiles are not configured
        in the endpoint profile list.

        Raises MultipleEndpointsMatch if the spe

        :param hostname: The name of the host the container is on.
        :param profile_names: The profiles to remove from the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Change the profile on the endpoint.
        ep = self.get_endpoint(**kwargs)
        for profile_name in profile_names:
            try:
                ep.profile_ids.remove(profile_name)
            except ValueError:
                raise ProfileNotInEndpoint(profile_name)
        self.update_endpoint(ep)

    @handle_errors
    def get_endpoint_id_from_cont(self, hostname, container_id):
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
        except EtcdKeyNotFound:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." %
                           container_id)

        # Get the first endpoint & ID
        try:
            endpoint = endpoints.next()
            (_, _, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 9)
            return endpoint_id
        except StopIteration:
            raise NoEndpointForContainer(
                "Container with ID %s has no endpoints." % container_id)

    @handle_errors
    def get_endpoints(self, hostname=None, orchestrator_id=None,
                      workload_id=None, endpoint_id=None):
        """
        Optimized function to get endpoint(s).

        Constructs a etcd-path that it as specific as possible given the
        provided criteria, in order to return the smallest etcd tree as
        possible. After querying with the ep_path, it will then compare the
        returned endpoints to the provided criteria, and return all matches.

        :param endpoint_id: The ID of the endpoint
        :param hostname: The hostname that the endpoint lives on.
        :param workload_id: The workload (or container) that the endpoint
        belongs to.
        :param orchestrator_id: The workload (or container) that the endpoint
        belongs to.
        :return: A list of Endpoint Objects which match the criteria, or an
        empty list if none match
        """
        # First build the query string as specific as possible. Note, we want
        # the query to be as specific as possible, so we proceed any variables
        # with known constants e.g. we add '/workload' after the hostname
        # variable.
        if not hostname:
            ep_path = ALL_ENDP_PATH
        elif not orchestrator_id:
            ep_path = HOST_ENDP_PATH % {"hostname": hostname}
        elif not workload_id:
            ep_path = ORCHESTRATOR_ENDP_PATH % {"hostname": hostname,
                                            "orchestrator_id": orchestrator_id}
        elif not endpoint_id:
            ep_path = WORKLOAD_ENDP_PATH % {"hostname": hostname,
                                           "orchestrator_id": orchestrator_id,
                                           "workload_id": workload_id}
        else:
            ep_path = ENDPOINT_ENDP_PATH % {"hostname": hostname,
                                            "orchestrator_id": orchestrator_id,
                                            "workload_id": workload_id,
                                            "endpoint_id": endpoint_id}
        try:
            # Search etcd
            leaves = self.etcd_client.read(ep_path, recursive=True).leaves
        except EtcdKeyNotFound:
            return []

        # Filter through result
        matches = []
        for leaf in leaves:
            endpoint = Endpoint.from_json(leaf.key, leaf.value)

            # If its an endpoint, compare it to search criteria
            if endpoint and endpoint.matches(hostname=hostname,
                                             orchestrator_id=orchestrator_id,
                                             workload_id=workload_id,
                                             endpoint_id=endpoint_id):
                matches.append(endpoint)
        return matches

    @handle_errors
    def get_endpoint(self, hostname=None, orchestrator_id=None,
                     workload_id=None, endpoint_id=None):
        """
        Calls through to get_endpoints to find an endpoint matching the
        passed-in criteria.
        Raises a MultipleEndpointsMatch exception if more than one endpoint
        matches.

        :return: An Endpoint Object
        """
        eps = self.get_endpoints(hostname=hostname,
                                 orchestrator_id=orchestrator_id,
                                 workload_id=workload_id,
                                 endpoint_id=endpoint_id)
        if not eps:
            raise KeyError("No endpoint found matching specified criteria")
        elif len(eps) > 1:
            raise MultipleEndpointsMatch()
        else:
            return eps.pop()

    @handle_errors
    def set_endpoint(self, hostname, container_id, endpoint):
        """
        Write a single endpoint object to the datastore.

        :param hostname: The hostname for the Docker hosting this container.
        :param container_id: The Docker container ID.
        :param endpoint: The Endpoint to add to the container.
        """
        ep_path = ENDPOINT_PATH % {"hostname": hostname,
                                   "container_id": container_id,
                                   "endpoint_id": endpoint.endpoint_id}
        new_json = endpoint.to_json()
        self.etcd_client.write(ep_path, new_json)
        endpoint._original_json = new_json

    @handle_errors
    def update_endpoint(self, endpoint):
        """
        Update a single endpoint object to the datastore.  This assumes the
        endpoint was originally queried from the datastore and updated.
        Example usage:
            endpoint = datastore.get_endpoint(...)
            # modify new endpoint fields
            datastore.update_endpoint(endpoint)

        :param endpoint: The Endpoint to add to the container.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "container_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        new_json = endpoint.to_json()
        self.etcd_client.write(ep_path,
                               new_json,
                               prevValue=endpoint._original_json)
        endpoint._original_json = new_json

    @handle_errors
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
                ep = Endpoint.from_json(child.key, child.value)
                if ep:
                    hosts[ep.hostname][ep.orchestrator_id][ep.workload_id][ep.endpoint_id] = ep
                else:
                    packed = child.key.split("/")
                    if 10 > len(packed) > 5:
                        (_, _, _, _, host, _) = packed[0:6]
                        if not hosts[host]:
                            hosts[host] = Vividict()
        except EtcdKeyNotFound:
            pass

        return hosts

    @handle_errors
    def get_default_next_hops(self, hostname):
        """
        Get the next hop IP addresses for default routes on the given host.

        :param hostname: The hostname for which to get default route next hops.
        :return: Dict of {ip_version: IPAddress}
        """

        host_path = HOST_PATH % {"hostname": hostname}
        try:
            ipv4 = self.etcd_client.read(host_path + "bird_ip").value
            ipv6 = self.etcd_client.read(host_path + "bird6_ip").value
        except EtcdKeyNotFound:
            raise KeyError("BIRD configuration for host %s not found." % hostname)

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

    @handle_errors
    def remove_all_data(self):
        """
        Remove all data from the datastore.

        We don't care if Calico data can't be found.

        """
        try:
            self.etcd_client.delete("/calico", recursive=True, dir=True)
        except EtcdKeyNotFound:
            pass

    @handle_errors
    def remove_container(self, hostname, container_id):
        """
        Remove a container from the datastore.
        :param hostname: The name of the host the container is on.
        :param container_id: The Docker container ID.
        :return: None.
        """
        container_path = CONTAINER_PATH % {"hostname": hostname,
                                           "container_id": container_id}
        try:
            self.etcd_client.delete(container_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured container on host %s" %
                           (container_id, hostname))

    @handle_errors
    def set_bgp_node_mesh(self, enable):
        """
        Set whether the BGP node mesh is enabled or not.

        :param enable: (Boolean) Whether the mesh is enabled or not.
        :return: None.
        """
        node_mesh = {"enabled": enable}
        self.etcd_client.write(BGP_NODE_MESH_PATH, json.dumps(node_mesh))

    @handle_errors
    def get_bgp_node_mesh(self):
        """
        Determine whether the BGP node mesh is enabled or not.

        :return: (Boolean) Whether the BGP node mesh is enabled.
        """
        try:
            node_mesh = json.loads(
                               self.etcd_client.read(BGP_NODE_MESH_PATH).value)
        except EtcdKeyNotFound:
            enabled = True
        else:
            enabled = node_mesh["enabled"]
        return enabled

    @handle_errors
    def set_default_node_as(self, as_num):
        """
        Return the default node BGP AS Number

        :return: The default node BGP AS Number.
        """
        self.etcd_client.write(BGP_NODE_DEF_AS_PATH, as_num)

    @handle_errors
    def get_default_node_as(self):
        """
        Return the default node BGP AS Number

        :return: The default node BGP AS Number.
        """
        try:
            as_num = self.etcd_client.read(BGP_NODE_DEF_AS_PATH).value
        except EtcdKeyNotFound:
            as_num = DEFAULT_AS_NUM

        return as_num


class NoEndpointForContainer(Exception):
    """
    Tried to get the endpoint associated with a container that has no
    endpoints.
    """
    pass


class DataStoreError(Exception):
    """
    General Datastore exception.
    """
    pass


class ProfileNotInEndpoint(Exception):
    """
    Attempting to remove a profile is not in the container endpoint profile
    list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class ProfileAlreadyInEndpoint(Exception):
    """
    Attempting to append a profile that is already in the container endpoint
    profile list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class MultipleEndpointsMatch(Exception):
    """
    More than one endpoint was found for the specified criteria.
    """
    pass
