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

import json
import os
import etcd
from etcd import EtcdKeyNotFound, EtcdException

from netaddr import IPNetwork, IPAddress, AddrFormatError

from calico_containers.pycalico.datastore_datatypes import Rules, BGPPeer, IPPool, \
    Endpoint, Profile, Rule
from calico_containers.pycalico.datastore_errors import DataStoreError, \
    ProfileNotInEndpoint, ProfileAlreadyInEndpoint, MultipleEndpointsMatch

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:4001"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

# etcd paths for Calico
CALICO_V_PATH = "/calico/v1"
CONFIG_PATH = CALICO_V_PATH + "/config/"
CONFIG_IF_PREF_PATH = CONFIG_PATH + "InterfacePrefix"
HOSTS_PATH = CALICO_V_PATH + "/host/"
HOST_PATH = HOSTS_PATH + "%(hostname)s/"
ORCHESTRATOR_PATH = HOST_PATH + "workload/%(orchestrator_id)s/"
WORKLOAD_PATH = ORCHESTRATOR_PATH + "%(workload_id)s/"
LOCAL_ENDPOINTS_PATH = WORKLOAD_PATH + "endpoint/"
ENDPOINT_PATH = LOCAL_ENDPOINTS_PATH + "%(endpoint_id)s"
PROFILES_PATH = CALICO_V_PATH + "/policy/profile/"
PROFILE_PATH = PROFILES_PATH + "%(profile_id)s/"
TAGS_PATH = PROFILE_PATH + "tags"
RULES_PATH = PROFILE_PATH + "rules"
IP_POOLS_PATH = CALICO_V_PATH + "/ipam/%(version)s/pool/"
IP_POOL_KEY = IP_POOLS_PATH + "%(pool)s"
BGP_PEERS_PATH = CALICO_V_PATH + "/config/bgp_peer_%(version)s/"
BGP_PEER_PATH = CALICO_V_PATH + "/config/bgp_peer_%(version)s/%(peer_ip)s"
BGP_NODE_DEF_AS_PATH = CONFIG_PATH + "bgp_as"
BGP_NODE_MESH_PATH = CONFIG_PATH + "bgp_node_mesh"
HOST_BGP_PEERS_PATH = HOST_PATH + "bgp_peer_%(version)s/"
HOST_BGP_PEER_PATH = HOST_PATH + "bgp_peer_%(version)s/%(peer_ip)s"

IF_PREFIX = "cali"
"""
prefix that appears in all Calico interface names in the root namespace. e.g.
cali123456789ab.
"""

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
        try:
            self.etcd_client.read(CONFIG_IF_PREF_PATH)
        except EtcdKeyNotFound:
            # Didn't exist, create it now.
            self.etcd_client.write(CONFIG_IF_PREF_PATH, IF_PREFIX)

        # We are always ready.
        self.etcd_client.write(CALICO_V_PATH + "/Ready", "true")

    @handle_errors
    def create_host(self, hostname, bird_ip, bird6_ip, as_num):
        """
        Create a new Calico host configuration in etcd.

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

        # Flag to Felix that the host is created.
        self.etcd_client.write(host_path + "config/marker", "created")

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
    def get_host_ips(self, hostname):
        """
        Check etcd for the configured IPv4 and IPv6 addresses for the specified
        host. If it hasn't been configured yet, raise an EtcdKeyNotFound.

        :param hostname: The hostname.
        :return: A tuple containing the IPv4 and IPv6 address.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        try:
            ipv4 = self.etcd_client.read(host_path + "bird_ip").value
            ipv6 = self.etcd_client.read(host_path + "bird6_ip").value
        except EtcdKeyNotFound:
            raise KeyError("BIRD configuration for host %s not found." % hostname)
        else:
            return (ipv4, ipv6)

    @handle_errors
    def get_ip_pools(self, version):
        """
        Get the configured IP pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of IPPool.
        """
        assert version in ("v4", "v6")
        pool_path = IP_POOLS_PATH % {"version": version}
        try:
            leaves = self.etcd_client.read(pool_path, recursive=True).leaves
        except EtcdKeyNotFound:
            # Path doesn't exist.
            pools = []
        else:
            # Convert the leaf values to IPPools.  We need to handle an empty
            # leaf value because when no pools are configured the recursive
            # read returns the parent directory.
            pools = [IPPool.from_json(leaf.value) for leaf in leaves
                                                  if leaf.value]

        return pools

    @handle_errors
    def get_ip_pool_config(self, version, cidr):
        """
        Get the configuration for the given pool.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: An IPPool object.
        """
        assert version in ("v4", "v6")
        assert isinstance(cidr, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        cidr = cidr.cidr

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(cidr).replace("/", "-")}

        try:
            data = self.etcd_client.read(key).value
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % cidr)

        return IPPool.from_json(data)

    @handle_errors
    def add_ip_pool(self, version, pool):
        """
        Add the given pool to the list of IP allocation pools.  If the pool
        already exists, this method completes silently without modifying the
        list of pools, other than possibly updating the ipip config.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPPool object
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPPool)

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(pool.cidr).replace("/", "-")}
        self.etcd_client.write(key, pool.to_json())

    @handle_errors
    def remove_ip_pool(self, version, cidr):
        """
        Delete the given CIDR range from the list of pools.  If the pool does
        not exist, raise a KeyError.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param cidr: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(cidr, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        cidr = cidr.cidr

        key = IP_POOL_KEY % {"version": version,
                             "pool": str(cidr).replace("/", "-")}
        try:
            self.etcd_client.delete(key)
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % cidr)

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
        Create a policy profile.  By default, endpoints in a profile
        accept traffic only from other endpoints in that profile, but can send
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
        # be accepted by another profile on the endpoint.
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
    def get_profile_members(self, profile_name):
        """
        Get the all of the endpoint members of a profile.

        :param profile_name: Unique string name of the profile.
        :return: a list of Endpoint objects.
        """
        return [endpoint for endpoint in self.get_endpoints()
                if profile_name in endpoint.profile_ids]

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
        single endpoint per workload.

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
        endpoint per workload.

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
        is a single endpoint per workload.

        Raises ProfileNotInEndpoint if any of the profiles are not configured
        in the endpoint profile list.

        Raises MultipleEndpointsMatch if the spe

        :param hostname: The name of the host the workload is on.
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
        :param workload_id: The workload that the endpoint belongs to.
        :param orchestrator_id: The workload that the endpoint belongs to.
        :return: A list of Endpoint Objects which match the criteria, or an
        empty list if none match
        """
        # First build the query string as specific as possible. Note, we want
        # the query to be as specific as possible, so we proceed any variables
        # with known constants e.g. we add '/workload' after the hostname
        # variable.
        if not hostname:
            ep_path = HOSTS_PATH
        elif not orchestrator_id:
            ep_path = HOST_PATH % {"hostname": hostname}
        elif not workload_id:
            ep_path = ORCHESTRATOR_PATH % {"hostname": hostname,
                                           "orchestrator_id": orchestrator_id}
        elif not endpoint_id:
            ep_path = WORKLOAD_PATH % {"hostname": hostname,
                                       "orchestrator_id": orchestrator_id,
                                       "workload_id": workload_id}
        else:
            ep_path = ENDPOINT_PATH % {"hostname": hostname,
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

        :param hostname: The hostname that the endpoint lives on.
        :param orchestrator_id: The workload that the endpoint belongs to.
        :param workload_id: The workload that the endpoint belongs to.
        :param endpoint_id: The ID of the endpoint
        :return: An Endpoint Object
        """
        eps = self.get_endpoints(hostname=hostname,
                                 orchestrator_id=orchestrator_id,
                                 workload_id=workload_id,
                                 endpoint_id=endpoint_id)
        if not eps:
            raise KeyError("No endpoint found matching specified criteria."
                           "hostname=%s"
                           "orchestrator_id=%s"
                           "workload_id=%s"
                           "endpoint_id=%s" % (hostname, orchestrator_id,
                                               workload_id, endpoint_id))
        elif len(eps) > 1:
            raise MultipleEndpointsMatch()
        else:
            return eps.pop()

    @handle_errors
    def set_endpoint(self, endpoint):
        """
        Write a single endpoint object to the datastore.

        :param endpoint: The Endpoint to add to the workload.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
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

        :param endpoint: The Endpoint to add to the workload.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        new_json = endpoint.to_json()
        self.etcd_client.write(ep_path,
                               new_json,
                               prevValue=endpoint._original_json)
        endpoint._original_json = new_json

    @handle_errors
    def remove_endpoint(self, endpoint):
        """
        Remove a single endpoint object from the datastore.

        :param endpoint: The Endpoint to remove.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        self.etcd_client.delete(ep_path, dir=True, recursive=True)

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
    def remove_workload(self, hostname, orchestrator_id, workload_id):
        """
        Remove a workload from the datastore.
        :param hostname: The name of the host the workload is on.
        :param orchestrator_id: The orchestrator the workload belongs to.
        :param workload_id: The workload ID.
        :return: None.
        """
        workload_path = WORKLOAD_PATH % {"hostname": hostname,
                                         "orchestrator_id": orchestrator_id,
                                         "workload_id": workload_id}
        try:
            self.etcd_client.delete(workload_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured workload on host %s" %
                           (workload_id, hostname))

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


