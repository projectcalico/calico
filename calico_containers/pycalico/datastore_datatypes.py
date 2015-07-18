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
import re

from netaddr import IPAddress, IPNetwork

VETH_NAME = "eth1"
"""The name to give to the veth in the target container's namespace. Default
to eth1 because eth0 could be in use"""

# The various datatype classes used by datastore.py are collected here.

class Rules(namedtuple("Rules", ["id", "inbound_rules", "outbound_rules"])):
    """
    A set of Calico rules describing inbound and outbound network traffic
    policy.
    """

    def to_json(self, indent=None):
        """
        Convert the Rules object to a JSON string.

        :param indent: Integer representing the level of indent from the
        returned json string. None = no indent, 0 = only newlines. Recommend
        using 1 for human-readable strings.
        :return:  A JSON string representation of this object.
        """
        json_dict = self._asdict()
        rules = json_dict["inbound_rules"]
        json_dict["inbound_rules"] = [rule.to_json_dict() for rule in rules]
        rules = json_dict["outbound_rules"]
        json_dict["outbound_rules"] = [rule.to_json_dict() for rule in rules]
        return json.dumps(json_dict, indent=indent)

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


class IPPool(object):
    """
    Class encapsulating an IPPool.
    """

    def __init__(self, cidr, ipip=False, masquerade=False):
        """
        Constructor.
        :param cidr: IPNetwork object (or CIDR string) representing the pool
        :param ipip: Use IP-IP for this pool.
        :param masquerade: Enable masquerade (outgoing NAT) for this pool.
        """
        # Normalize the CIDR (e.g. 1.2.3.4/16 -> 1.2.0.0/16)
        self.cidr = IPNetwork(cidr).cidr
        self.ipip = bool(ipip)
        self.masquerade = bool(masquerade)

    def to_json(self):
        """
        Convert the IPPool to a JSON string.
        :return: A JSON string.
        """
        json_dict = {"cidr" : str(self.cidr)}
        if self.ipip:
            json_dict["ipip"] = "tunl0"
        if self.masquerade:
            json_dict["masquerade"] = True
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, json_str):
        """
        Convert the json string into a IPPool object.
        :param json_str: The JSON string representing an IPPool.
        :return: An IPPool object.
        """
        json_dict = json.loads(json_str)
        return cls(json_dict["cidr"],
                   ipip=json_dict.get("ipip"),
                   masquerade=json_dict.get("masquerade"))

    def __eq__(self, other):
        if not isinstance(other, IPPool):
            return NotImplemented
        return (self.cidr == other.cidr and
                self.ipip == other.ipip and
                self.masquerade == other.masquerade)

    def __contains__(self, item):
        """
        Override __contains__ so that you can check if an IP address is in this
        pool.

        e.g. IPAddress("1.2.3.4) in IPPool("1.2.3.0/24") is True.
        """
        return IPAddress(item) in self.cidr

    def __str__(self):
        """Return the CIDR of this pool."""
        return str(self.cidr)


class Endpoint(object):
    """
    Class encapsulating an Endpoint.
    This class keeps track of the original JSON representation of the
    endpoint to allow atomic updates to be performed.
    """
    # Endpoint path match regex
    ENDPOINT_KEY_MATCH = re.compile("/calico/v1/host/(?P<hostname>[^/]*)/"
                                "workload/(?P<orchestrator_id>[^/]*)/"
                                "(?P<workload_id>[^/]*)/"
                                "endpoint/(?P<endpoint_id>[^/]*)")

    def __init__(self, hostname, orchestrator_id, workload_id, endpoint_id,
                 state, mac):
        self.hostname = hostname
        self.orchestrator_id = orchestrator_id
        self.workload_id = workload_id
        self.endpoint_id = endpoint_id
        self.state = state
        self.mac = mac
        self.name = "cali" + endpoint_id[:11]

        self.ipv4_nets = set()
        self.ipv6_nets = set()
        self.ipv4_gateway = None
        self.ipv6_gateway = None

        self.if_name = None
        self.profile_ids = []
        self._original_json = None

    def to_json(self):
        json_dict = {"state": self.state,
                     "name": self.name,
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
        match = Endpoint.ENDPOINT_KEY_MATCH.match(endpoint_key)
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

        :param hostname: The hostname to compare to
        :param orchestrator_id: The orchestrator ID to compare to.
        :param workload_id: The workload ID to compare to
        :param endpoint_id: The endpoint ID to compare to

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

    def temp_interface_name(self):
        return "tmp" + self.endpoint_id[:11]

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "Endpoint(%s)" % self.to_json()


class Profile(object):
    """A Calico policy profile."""

    def __init__(self, name):
        self.name = name
        self.tags = set()

        # Default to empty lists of rules.
        self.rules = Rules(name, [], [])


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
            out.extend(["cidr", str(self["src_net"])])

        if "dst_tag" in self or "dst_ports" in self or "dst_net" in self:
            out.append("to")
        if "dst_ports" in self:
            ports = ",".join(str(p) for p in self["dst_ports"])
            out.extend(["ports", ports])
        if "dst_tag" in self:
            out.extend(["tag", self["dst_tag"]])
        if "dst_net" in self:
            out.extend(["cidr", str(self["dst_net"])])

        return " ".join(out)