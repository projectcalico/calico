# -*- coding: utf-8 -*-
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
"""
felix.fiptgenerator.py
~~~~~~~~~~~~

Default implementation of the Felix iptables Generator plugin.   This module is
responsible for generating the vast majority of rules that get programmed to
iptables.   Specifically this includes:
 - the per endpoint chains
 - the per profile chains
 - the global Felix PREROUTING, INPUT and FORWARD chains.
 Exceptions are the single rules that get inserted into the top level kernel
 chains (owned instead by the felix.frules module) and the dispatch chains
 that fan packets out to the appropriate endpoint chains
 (owned instead by felix.dispatch).

This module is loaded by core Felix as a plugin via the
calico.felix.iptables_generator entrypoint, making it theoretically possible
for alternative implementations to be loaded instead.   However, this interface
is currently HIGHLY EXPERIMENTAL.  It should not be considered stable, and may
change significantly, or be removed completely, in future releases.

"""

import logging
import re
import itertools

from calico.common import KNOWN_RULE_KEYS
from calico.felix import futils
from calico.felix.fplugin import FelixPlugin
from calico.felix.profilerules import UnsupportedICMPType
from calico.felix.frules import (CHAIN_TO_ENDPOINT, CHAIN_FROM_ENDPOINT,
                                 CHAIN_TO_PREFIX, CHAIN_FROM_PREFIX,
                                 CHAIN_PREROUTING, CHAIN_INPUT, CHAIN_FORWARD,
                                 FELIX_PREFIX)

CHAIN_PROFILE_PREFIX = FELIX_PREFIX + "p-"

_log = logging.getLogger(__name__)

# Maximum number of port entries in a "multiport" match rule.  Ranges count for
# 2 entries.
MAX_MULTIPORT_ENTRIES = 15


class FelixIptablesGenerator(FelixPlugin):
    """
    Felix plugin responsible for generating the actual rules that get written
    to iptables.
    """
    def __init__(self):
        self.IFACE_PREFIX = None
        self.IFACE_MATCH = None
        self.DEFAULT_INPUT_CHAIN_ACTION = None
        self.METADATA_IP = None
        self.METADATA_PORT = None

    def store_and_validate_config(self, config):
        # We don't have any plugin specific parameters, but we need to save
        # off any other global config that we're interested in at this point.

        super(FelixIptablesGenerator, self).store_and_validate_config(config)

        self.IFACE_PREFIX = config.IFACE_PREFIX
        self.IFACE_MATCH = self.IFACE_PREFIX + "+"
        self.METADATA_IP = config.METADATA_IP
        self.METADATA_PORT = config.METADATA_PORT
        self.DEFAULT_INPUT_CHAIN_ACTION = config.DEFAULT_INPUT_CHAIN_ACTION

    def raw_rpfilter_failed_chain(self, ip_version):
        """
        Generate the RAW felix-PREROUTING chain -- currently only IPv6.

        Returns a list of iptables fragments with which to program the
        felix-PREROUTING chain that is invoked from the IPv6 RAW PREROUTING
        kernel chain.  Note this chain is ONLY INVOKED in the case that packets
        fail the rpfilter match.

        The list returned here should be the complete set of rules required
        as any existing chain will be overwritten.

        :param ip_version.  Currently always 6.
        :returns Tuple: list of rules, set of deps.
        """

        # We only program this chain for IPv6
        assert ip_version == 6

        chain = self.drop_rules(ip_version,
                                CHAIN_PREROUTING,
                                None,
                                "IPv6 rpfilter failed")
        return chain, {}

    def nat_prerouting_chain(self, ip_version):
        """
        Generate the NAT felix-PREROUTING chain -- currently only IPv4.

        Returns a list of iptables fragments with which to program the
        felix-PREROUTING chain which is unconditionally invoked from the IPv4
        NAT PREROUTING chain.

        Note that the list returned here should be the complete set of rules
        required as any existing chain will be overwritten.

        :param ip_version.  Currently always 4.
        :returns Tuple: list of rules, set of deps.
        """

        # We only program this chain for IPv4
        assert ip_version == 4

        chain = []
        if self.METADATA_IP is not None:
            # Need to expose the metadata server on a link-local.
            #  DNAT tcp -- any any anywhere 169.254.169.254
            #              tcp dpt:http to:127.0.0.1:9697
            chain = [
                "--append " + CHAIN_PREROUTING + " "
                "--protocol tcp "
                "--dport 80 "
                "--destination 169.254.169.254/32 "
                "--jump DNAT --to-destination %s:%s" %
                (self.METADATA_IP, self.METADATA_PORT)]

        return chain, {}

    def filter_input_chain(self, ip_version, hosts_set_name=None):
        """
        Generate the IPv4/IPv6 FILTER felix-INPUT chains.

        Returns a list of iptables fragments with which to program the
        felix-INPUT chain that is unconditionally invoked from both the IPv4
        and IPv6 FILTER INPUT kernel chains.

        Note that the list returned here should be the complete set of rules
        required as any existing chain will be overwritten.

        :param ip_version.  Whether this is the IPv4 or IPv6 FILTER table.
        :returns Tuple: list of rules, set of deps.
        """

        if ip_version == 4:
            metadata_addr = self.METADATA_IP
            metadata_port = self.METADATA_PORT
            dhcp_src_port = 68
            dhcp_dst_port = 67
        else:
            metadata_addr = None
            metadata_port = None
            dhcp_src_port = 546
            dhcp_dst_port = 547

        chain = []
        deps = set()

        if hosts_set_name:
            # IP-in-IP enabled, drop any IP-in-IP packets that are not from
            # other Calico hosts.
            _log.info("IPIP enabled, dropping IPIP packets from non-Calico "
                      "hosts.")
            # The ipencap proctol uses the ID "4". Some versions of iptables
            # can't understand protocol names.
            chain.extend(self.drop_rules(
                ip_version,
                CHAIN_INPUT,
                "--protocol 4 --match set "
                "! --match-set %s src" % hosts_set_name,
                None)
            )

        # Optimisation: return immediately if the traffic is not from one of
        # the interfaces we're managing.
        chain.append("--append %s ! --in-interface %s --jump RETURN" %
                     (CHAIN_INPUT, self.IFACE_MATCH,))

        # Allow established connections via the conntrack table.
        chain.extend(self.drop_rules(ip_version,
                                     CHAIN_INPUT,
                                     "--match conntrack --ctstate INVALID",
                                     None))
        chain.append("--append %s --match conntrack "
                     "--ctstate RELATED,ESTABLISHED --jump ACCEPT" %
                     CHAIN_INPUT)

        # To act as a router for IPv6, we have to accept various types of
        # ICMPv6 messages, as follows:
        #
        # - 130: multicast listener query.
        # - 131: multicast listener report.
        # - 132: multicast listener done.
        # - 133: router solicitation, which an endpoint uses to request
        #        configuration information rather than waiting for an
        #        unsolicited router advertisement.
        # - 135: neighbor solicitation.
        # - 136: neighbor advertisement.
        if ip_version == 6:
            for icmp_type in ["130", "131", "132", "133", "135", "136"]:
                chain.append("--append %s --jump ACCEPT "
                             "--protocol ipv6-icmp "
                             "--icmpv6-type %s" %
                             (CHAIN_INPUT, icmp_type))

        if metadata_addr is not None:
            _log.info("Metadata address specified, whitelisting metadata "
                      "service")
            chain.append(
                "--append %s --protocol tcp "
                "--destination %s --dport %s --jump ACCEPT" %
                (CHAIN_INPUT, metadata_addr, metadata_port)
            )

        # Special-case: allow DHCP.
        chain.append(
            "--append %s --protocol udp --sport %d "
            "--dport %s --jump ACCEPT" %
            (CHAIN_INPUT, dhcp_src_port, dhcp_dst_port)
        )

        # Special-case: allow DNS.
        dns_dst_port = 53
        chain.append(
            "--append %s --protocol udp --dport %s --jump ACCEPT" %
            (CHAIN_INPUT, dns_dst_port)
        )

        if self.DEFAULT_INPUT_CHAIN_ACTION != "DROP":
            # Optimisation: the from-ENDPOINT chain signals acceptance of a
            # packet by RETURNing.  If we're going to drop the packet
            # anyway, don't bother applying the from-ENDPOINT chain.
            _log.info("Default endpoint->host action set to %s, felix will "
                      "apply per-endpoint policy to packets in the INPUT "
                      "chain.",
                      self.DEFAULT_INPUT_CHAIN_ACTION)
            chain.append(
                "--append %s --jump %s" %
                (CHAIN_INPUT, CHAIN_FROM_ENDPOINT)
            )
            deps.add(CHAIN_FROM_ENDPOINT)

        if self.DEFAULT_INPUT_CHAIN_ACTION != "RETURN":
            # Optimisation: RETURN is the default if the packet reaches the end
            # of the chain so no need to program it.
            if self.DEFAULT_INPUT_CHAIN_ACTION == "DROP":
                chain.extend(self.drop_rules(ip_version,
                                             CHAIN_INPUT,
                                             None,
                                             "Drop all packets from "
                                             "endpoints to the host"))
            else:
                chain.append(
                    "--append %s --jump %s" %
                    (CHAIN_INPUT, self.DEFAULT_INPUT_CHAIN_ACTION)
                )

        return chain, deps
 
    def filter_forward_chain(self, ip_version):
        """
        Generate the IPv4/IPv6 FILTER felix-FORWARD chains.

        Returns a list of iptables fragments with which to program the
        felix-FORWARD chain that is unconditionally invoked from both the IPv4
        and IPv6 FILTER FORWARD kernel chains.

        Note that the list returned here should be the complete set of rules
        required as any existing chain will be overwritten.

        :param ip_version.  Whether this is the IPv4 or IPv6 FILTER table.
        :returns Tuple: list of rules, set of deps.
        """
        forward_chain = (
            self.drop_rules(ip_version,
                            CHAIN_FORWARD,
                            "--in-interface %s --match conntrack --ctstate "
                            "INVALID" % self.IFACE_MATCH,
                            None) +
            self.drop_rules(ip_version,
                            CHAIN_FORWARD,
                            "--out-interface %s --match conntrack --ctstate "
                            "INVALID" % self.IFACE_MATCH,
                            None) +
            [
                "--append %s --in-interface %s --match conntrack "
                "--ctstate RELATED,ESTABLISHED --jump RETURN" %
                (CHAIN_FORWARD, self.IFACE_MATCH),
                "--append %s --out-interface %s --match conntrack "
                "--ctstate RELATED,ESTABLISHED --jump RETURN" %
                (CHAIN_FORWARD, self.IFACE_MATCH),
                "--append %s --jump %s --in-interface %s" %
                (CHAIN_FORWARD, CHAIN_FROM_ENDPOINT, self.IFACE_MATCH),
                "--append %s --jump %s --out-interface %s" %
                (CHAIN_FORWARD, CHAIN_TO_ENDPOINT, self.IFACE_MATCH),
                "--append %s --jump ACCEPT --in-interface %s" %
                (CHAIN_FORWARD, self.IFACE_MATCH),
                "--append %s --jump ACCEPT --out-interface %s" %
                (CHAIN_FORWARD, self.IFACE_MATCH),
            ]
        )
        return forward_chain, set([CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT])

    def endpoint_chain_names(self, endpoint_suffix):
        """
        Returns the set of chains belonging to a given endpoint.  This is used
        e.g. to identify the set of chains that should be deleted to clean up
        a endpoint.

        :param endpoint_suffix: The suffix of the endpoint we want to know
        the chains for.
        :returns set[string]: the set of chain names
        """
        to_chain_name = (CHAIN_TO_PREFIX + endpoint_suffix)
        from_chain_name = (CHAIN_FROM_PREFIX + endpoint_suffix)
        return set([to_chain_name, from_chain_name])

    def endpoint_updates(self, ip_version, endpoint_id, suffix, mac,
                         profile_ids):
        """
        Generate a set of iptables updates that will program all of the chains
        needed for a given endpoint.

        For each endpoint the following two top level chains must be defined
        as they are referenced from the dispatch chains programmed by core
        Felix.
        - CHAIN_TO_PREFIX + endpoint_suffix
        - CHAIN_FROM_PREFIX + endpoint_suffix

        :param ip_version.  Whether these are for the IPv4 or IPv6 iptables.
        :param endpoint_id: The endpoint's ID.
        :param suffix:  The endpoint's suffix.
        :param mac: The endpoint's MAC address
        :param profile_ids: the set of profile_ids associated with this
        endpoint

        :returns Tuple: updates, deps
        """

        to_chain_name = (CHAIN_TO_PREFIX + suffix)
        from_chain_name = (CHAIN_FROM_PREFIX + suffix)

        to_chain, to_deps = self._build_to_or_from_chain(
            ip_version,
            endpoint_id,
            profile_ids,
            to_chain_name,
            "inbound"
        )
        from_chain, from_deps = self._build_to_or_from_chain(
            ip_version,
            endpoint_id,
            profile_ids,
            from_chain_name,
            "outbound",
            expected_mac=mac,
        )

        updates = {to_chain_name: to_chain, from_chain_name: from_chain}
        deps = {to_chain_name: to_deps, from_chain_name: from_deps}
        return updates, deps

    def profile_chain_names(self, profile_id):
        """
        Returns the set of chains belonging to a given profile.  This is used
        e.g. to identify the set of chains that should be deleted to clean up
        a profile.

        :param profile_id: The profile ID we want to know the chains for.
        :returns set[string]: the set of chain names
        """
        return set([self._profile_to_chain_name("inbound", profile_id),
                    self._profile_to_chain_name("outbound", profile_id)])

    def profile_updates(self, profile_id, profile, ip_version, tag_to_ipset,
                        on_allow="ACCEPT", on_deny="DROP", comment_tag=None):
        """
        Generate a set of iptables updates that will program all of the chains
        needed for a given profile.

        :returns Tuple: updates, deps
        """

        # Generates an inbound and an outbound chain for each profile.
        # Within each chain, the logic is as follows:
        # * Start by marking all packets.
        # * If we hit an allow rule, we'll return with the mark still set, to
        #   indicate that we matched.
        # * If we hit a deny rule, we'll drop the packet immediately.
        # * If we reach the end of the chain, we'll un-mark the packet again to
        #   indicate no match.

        updates = {}
        deps = {}

        for direction in ("inbound", "outbound"):

            chain_name = self._profile_to_chain_name(direction, profile_id)
            rules_key = "%s_rules" % direction
            rules = profile.get(rules_key, [])

            fragments = [
                '--append %s --jump MARK --set-mark 1' % chain_name
            ]
            for r in rules:
                rule_version = r.get('ip_version')
                if rule_version is None or rule_version == ip_version:
                    fragments.extend(self._rule_to_iptables_fragments(
                        chain_name,
                        r,
                        ip_version,
                        tag_to_ipset,
                        on_allow=on_allow,
                        on_deny=on_deny))

            # If we get to the end of the chain without a match, we remove the
            # mark again to indicate that the packet wasn't matched.
            fragments.append(
                '--append %s '
                '--match comment --comment '
                '"No match, fall through to next profile" '
                '--jump MARK --set-mark 0' % chain_name
            )
            updates[chain_name] = fragments

        return updates, deps

    def drop_rules(self, ip_version, chain_name, rule_spec=None, comment=None,
                   ipt_action="--append"):
        """
        Return a list of iptables updates that can be applied to a chain to
        drop packets that meet a given rule_spec.
        :param ip_version.  Whether these are for the IPv4 or IPv6 iptables.
        :param chain_name: the chain that the updates will be applied to
        :param rule_spec: the rule spec (e.g. match criteria).   May be None
        to drop all packets.
        :param comment: any comment that should be associated with the
        rule.  May be None to not include a comment.
        :param ipt_action: the action that should be used to apply the rule
        (e.g. --append or --insert)

        :return list: a list of iptables fragments of the form
        [ipt_action] [chain_name] [rule_spec] [action] [comment] e.g.
        --append my_chain --match conntrack --ctstate INVALID --jump DROP
        """
        comment_str = None
        if comment is not None:
            comment = comment[:255]  # Limit imposed by iptables.
            assert re.match(r'[\w: ]{,255}', comment), \
                "Invalid comment %r" % comment
            comment_str = '-m comment --comment "%s"' % comment

        parts = [p for p in [ipt_action,
                             chain_name,
                             rule_spec,
                             '--jump DROP',
                             comment_str]
                 if p is not None]
        return [' '.join(parts)]

    def _build_to_or_from_chain(self, ip_version, endpoint_id, profile_ids,
                                chain_name, direction, expected_mac=None):
        """
        Generate the necessary set of iptables fragments for a to or from
        chain for a given endpoint.

        :param ip_version.  Whether this chain is for IPv4 or IPv6 iptables.
        :param endpoint_id: The endpoint's ID.
        :param profile_ids: The set of profile_ids associated with this
        endpoint.
        :param chain_name: The name of the chain to generate.
        :param direction: One of "inbound" or "outbound".
        :param expected_mac: The expected source MAC address.   If not None
        then the chain will explicitly drop any packets that do not have this
        expected source MAC address.

        :returns Tuple: chain, deps.   Chain is a list of fragments that can
        be submitted to iptables to program the requested chain.  Deps is a
        set containing names of chains that this endpoint chain depends on.
        """

        # Ensure the MARK is set to 0 when we start so that unmatched packets
        # will be dropped.
        chain = [
            "--append %s --jump MARK --set-mark 0" % chain_name
        ]
        if expected_mac:
            _log.debug("Policing source MAC: %s", expected_mac)
            chain.extend(self.drop_rules(
                ip_version,
                chain_name,
                "--match mac ! --mac-source %s" % expected_mac,
                "Incorrect source MAC"))

        # Jump to each profile in turn.  The profile will do one of the
        # following:
        # * DROP the packet; in which case we won't see it again.
        # * RETURN the packet with MARK==1, indicating it accepted the packet.
        #   In which case, we RETURN and skip further profiles.
        # * RETURN the packet with MARK==0, indicating it did not match the
        #   packet.  In which case, we carry on and process the next profile.
        deps = set()
        for profile_id in profile_ids:
            profile_chain = self._profile_to_chain_name(direction, profile_id)
            deps.add(profile_chain)
            chain.append("--append %s --jump %s" % (chain_name, profile_chain))
            # If the profile accepted the packet, it sets MARK==1.  Immediately
            # RETURN the packet to signal that it's been accepted.
            chain.append('--append %s --match mark --mark 1/1 '
                         '--match comment --comment "Profile accepted packet" '
                         '--jump RETURN' % chain_name)

        # Default drop rule.
        chain.extend(
            self.drop_rules(
                ip_version,
                chain_name,
                None,
                "Packet did not match any profile (endpoint %s)" % endpoint_id
            )
        )
        return chain, deps

    def _profile_to_chain_name(self, inbound_or_outbound, profile_id):
        """
        Returns the name of the chain to use for a given profile (and
        direction).

        The profile ID that we are supplied might be (far) too long for us
        to use, but truncating it is dangerous (for example, in OpenStack
        the profile is the ID of each security group in use, joined with
        underscores). Hence we make a unique string out of it and use that.

        :param inbound_or_outbound: Either "inbound" or "outbound".
        :param profile_id: The profile ID we want to know a name for.
        :returns string: The name of the chain
        """
        profile_string = futils.uniquely_shorten(profile_id, 16)
        return CHAIN_PROFILE_PREFIX + "%s-%s" % (profile_string,
                                                 inbound_or_outbound[:1])

    def _rule_to_iptables_fragments(self, chain_name, rule, ip_version,
                                    tag_to_ipset, on_allow="ACCEPT",
                                    on_deny="DROP"):
        """
        Convert a rule dict to a list of iptables fragments suitable to use
        with iptables-restore.

        Most rules result in result list containing one item.

        :param str chain_name: Name of the chain this rule belongs to (used in
               the --append)
        :param dict[str,str|list|int] rule: Rule dict.
        :param ip_version.  Whether these are for the IPv4 or IPv6 iptables.
        :param dict[str] tag_to_ipset: dictionary mapping from tag key to ipset
               name.
        :param str on_allow: iptables action to use when the rule allows
               traffic.  For example: "ACCEPT" or "RETURN".
        :param str on_deny: iptables action to use when the rule denies
               traffic.  For example: "DROP".
        :return list[str]: iptables --append fragments.
        """

        # Check we've not got any unknown fields.
        unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
        assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

        # Ports are special, we have a limit on the number of ports that can go
        # in one rule so we need to break up rules with a lot of ports into
        # chunks. We take the cross product of the chunks to cover all the
        # combinations. If there are not ports or if there are only a few ports
        # then the cross product ends up with only one entry.
        src_ports = rule.get("src_ports", [])
        dst_ports = rule.get("dst_ports", [])
        src_port_chunks = self._split_port_lists(src_ports)
        dst_port_chunks = self._split_port_lists(dst_ports)
        # Only need a shallow copy so we can replace ports.
        rule_copy = dict(rule)

        try:
            fragments = []
            for src_ports, dst_ports in itertools.product(src_port_chunks,
                                                          dst_port_chunks):
                rule_copy["src_ports"] = src_ports
                rule_copy["dst_ports"] = dst_ports
                frags = self._rule_to_iptables_fragments_inner(
                    chain_name,
                    rule_copy,
                    ip_version,
                    tag_to_ipset,
                    on_allow=on_allow,
                    on_deny=on_deny)
                fragments.extend(frags)

            return fragments

        except Exception as e:
            # Defensive: isolate failures to parse the rule (which has already
            # passed validation by this point) to this chain.
            _log.exception("Failed to parse rules: %r", e)
            return self.drop_rules(ip_version,
                                   chain_name,
                                   None,
                                   "ERROR failed to parse rules")

    def _split_port_lists(self, ports):
        """
        Splits a list of ports and port ranges into chunks that are
        small enough to use with the multiport match.

        :param list[str|int] ports: list of ports or ranges, specified with
                                    ":"; for example, '1024:6000'
        :return list[list[str]]: list of chunks.  If the input is empty, then
                                 returns a list containing a single empty list.
        """
        chunks = []
        chunk = []
        entries_in_chunk = 0
        for port_or_range in ports:
            port_or_range = str(port_or_range)  # Defensive, support ints too.
            if ":" in port_or_range:
                # This is a range, which counts for 2 entries.
                num_entries = 2
            else:
                # Just a port.
                num_entries = 1
            if entries_in_chunk + num_entries > MAX_MULTIPORT_ENTRIES:
                chunks.append(chunk)
                chunk = []
                entries_in_chunk = 0
            chunk.append(port_or_range)
            entries_in_chunk += num_entries
        if chunk or not chunks:
            chunks.append(chunk)
        return chunks

    def _rule_to_iptables_fragments_inner(self, chain_name, rule, ip_version,
                                          tag_to_ipset, on_allow="ACCEPT",
                                          on_deny="DROP"):
        """
        Convert a rule dict to iptables fragments suitable to use with
        iptables-restore.

        :param str chain_name: Name of the chain this rule belongs to (used in
                the --append)
        :param dict[str,str|list|int] rule: Rule dict.
        :param ip_version.  Whether these are for the IPv4 or IPv6 iptables.
        :param dict[str] tag_to_ipset: dictionary mapping from tag key to ipset
               name.
        :param str on_allow: iptables action to use when the rule allows
                traffic. For example: "ACCEPT" or "RETURN".
        :param str on_deny: iptables action to use when the rule denies
                traffic. For example: "DROP".
        :returns list[str]: list of iptables --append fragments.
        """

        # Check we've not got any unknown fields.
        unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
        assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

        # Build up the update in chunks and join them below.
        rule_spec = []
        append = lambda *args: rule_spec.extend(args)

        proto = rule.get("protocol")
        if proto:
            proto = rule["protocol"]
            append("--protocol", str(proto))

        for dirn in ["src", "dst"]:
            # Some params use the long-form of the name.
            direction = "source" if dirn == "src" else "destination"

            # Network (CIDR).
            net_key = dirn + "_net"
            if net_key in rule and rule[net_key] is not None:
                ip_or_cidr = rule[net_key]
                if (":" in ip_or_cidr) == (ip_version == 6):
                    append("--%s" % direction, ip_or_cidr)

            # Tag, which maps to an ipset.
            tag_key = dirn + "_tag"
            if tag_key in rule and rule[tag_key] is not None:
                ipset_name = tag_to_ipset[rule[tag_key]]
                append("--match set", "--match-set", ipset_name, dirn)

            # Port lists/ranges, which we map to multiport. Ignore not just
            # "None" but also an empty list.
            ports_key = dirn + "_ports"
            if ports_key in rule and rule[ports_key]:
                assert proto in ["tcp", "udp"], \
                    "Protocol %s not supported with %s (%s)" % \
                    (proto, ports_key, rule)
                ports = ','.join([str(p) for p in rule[ports_key]])
                # multiport only supports 15 ports.  The calling function
                # should have taken care of that.
                num_ports = ports.count(",") + ports.count(":") + 1
                assert num_ports <= 15, "Too many ports (%s)" % ports
                append("--match multiport", "--%s-ports" % direction, ports)

        if rule.get("icmp_type") is not None:
            icmp_type = rule["icmp_type"]
            if icmp_type == 255:
                # Temporary work-around for this issue:
                # https://github.com/projectcalico/calico/issues/451
                # This exception will be caught by the caller, which will
                # replace this rule with a DROP rule.  That's arguably better
                # than forbidding this case in the validation routine, which
                # would replace the whole chain with a DROP.
                _log.error("Kernel doesn't support matching on ICMP type 255.")
                raise UnsupportedICMPType()
            assert isinstance(icmp_type, int), "ICMP type should be an int"
            if "icmp_code" in rule:
                icmp_code = rule["icmp_code"]
                assert isinstance(icmp_code, int), "ICMP code should be an int"
                icmp_filter = "%s/%s" % (icmp_type, icmp_code)
            else:
                icmp_filter = icmp_type
            if proto == "icmp" and ip_version == 4:
                append("--match icmp", "--icmp-type", icmp_filter)
            elif ip_version == 6:
                assert proto == "icmpv6"
                # Note variant spelling of icmp[v]6
                append("--match icmp6", "--icmpv6-type", icmp_filter)

        action = on_allow if rule.get("action", "allow") == "allow" \
                 else on_deny
        rule_spec_str = " ".join(str(x) for x in rule_spec)

        if action == "DROP":
            return self.drop_rules(ip_version, chain_name, rule_spec_str, None)
        else:
            return [" ".join([
                    "--append",
                    chain_name,
                    rule_spec_str,
                    "--jump",
                    action])]
