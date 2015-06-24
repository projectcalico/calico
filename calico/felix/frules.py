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
felix.frules
~~~~~~~~~~~~

Felix rule management, including iptables and ipsets.
"""
import logging
import itertools
from calico.felix import devices
from calico.felix import futils
from calico.common import KNOWN_RULE_KEYS
import re
from calico.felix.ipsets import HOSTS_IPSET_V4

_log = logging.getLogger(__name__)

# Maximum number of port entries in a "multiport" match rule.  Ranges count for
# 2 entries.
MAX_MULTIPORT_ENTRIES = 15

# Chain names
FELIX_PREFIX = "felix-"
CHAIN_PREROUTING = FELIX_PREFIX + "PREROUTING"
CHAIN_INPUT = FELIX_PREFIX + "INPUT"
CHAIN_FORWARD = FELIX_PREFIX + "FORWARD"
CHAIN_TO_ENDPOINT = FELIX_PREFIX + "TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = FELIX_PREFIX + "FROM-ENDPOINT"
CHAIN_TO_LEAF = FELIX_PREFIX + "TO-EP-PFX"
CHAIN_FROM_LEAF = FELIX_PREFIX + "FROM-EP-PFX"
CHAIN_TO_PREFIX = FELIX_PREFIX + "to-"
CHAIN_FROM_PREFIX = FELIX_PREFIX + "from-"
CHAIN_PROFILE_PREFIX = FELIX_PREFIX + "p-"

# Name of the global, stateless IP-in-IP device name.
IP_IN_IP_DEV_NAME = "tunl0"


def profile_to_chain_name(inbound_or_outbound, profile_id):
    """
    Returns the name of the chain to use for a given profile. The profile ID
    that we are supplied might be (far) too long for us to use, but truncating
    it is dangerous (for example, in OpenStack the profile is the ID of each
    security group in use, joined with underscores). Hence we make a unique
    string out of it and use that.
    """
    profile_string = futils.uniquely_shorten(profile_id, 16)
    return CHAIN_PROFILE_PREFIX + "%s-%s" % (profile_string,
                                             inbound_or_outbound[:1])


def install_global_rules(config, v4_filter_updater, v6_filter_updater,
                         v4_nat_updater):
    """
    Set up global iptables rules. These are rules that do not change with
    endpoint, and are expected never to change (such as the rules that send all
    traffic through the top level Felix chains).

    This method therefore :

    - ensures that all the required global tables are present;
    - applies any changes required.
    """

    # The interface matching string; for example, if interfaces start "tap"
    # then this string is "tap+".
    iface_match = config.IFACE_PREFIX + "+"

    # If enabled, create the IP-in-IP device
    if config.IP_IN_IP_ENABLED:
        _log.info("IP-in-IP enabled, ensuring device exists.")
        if not devices.interface_exists(IP_IN_IP_DEV_NAME):
            # Make sure the IP-in-IP device exists; since we use the global
            # device, this command actually creates it as a side-effect of
            # initialising the kernel module rather than explicitly creating
            # it.
            _log.info("Tunnel device didn't exist; creating.")
            futils.check_call(["ip", "tunnel", "add", IP_IN_IP_DEV_NAME,
                               "mode", "ipip"])
        if not devices.interface_up(IP_IN_IP_DEV_NAME):
            _log.info("Tunnel device wasn't up; enabling.")
            futils.check_call(["ip", "link", "set", IP_IN_IP_DEV_NAME, "up"])

    # The IPV4 nat table first. This must have a felix-PREROUTING chain.
    nat_pr = []
    if config.METADATA_IP is not None:
        # Need to expose the metadata server on a link-local.
        #  DNAT tcp -- any any anywhere 169.254.169.254
        #              tcp dpt:http to:127.0.0.1:9697
        nat_pr.append("--append " + CHAIN_PREROUTING + " "
                      "--protocol tcp "
                      "--dport 80 "
                      "--destination 169.254.169.254/32 "
                      "--jump DNAT --to-destination %s:%s" %
                      (config.METADATA_IP, config.METADATA_PORT))
    v4_nat_updater.rewrite_chains({CHAIN_PREROUTING: nat_pr}, {}, async=False)
    v4_nat_updater.ensure_rule_inserted(
        "PREROUTING --jump %s" % CHAIN_PREROUTING, async=False)

    # Now the filter table. This needs to have calico-filter-FORWARD and
    # calico-filter-INPUT chains, which we must create before adding any
    # rules that send to them.
    for iptables_updater, hosts_set in [(v4_filter_updater, HOSTS_IPSET_V4),
                                        # FIXME support IP-in-IP for IPv6.
                                        (v6_filter_updater, None)]:
        if hosts_set and config.IP_IN_IP_ENABLED:
            hosts_set_name = hosts_set.set_name
        else:
            hosts_set_name = None
        if iptables_updater is v4_filter_updater:
            input_chain, input_deps = _build_input_chain(
                iface_match=iface_match,
                metadata_addr=config.METADATA_IP,
                metadata_port=config.METADATA_PORT,
                dhcp_src_port=68,
                dhcp_dst_port=67,
                ipv6=False,
                default_action=config.DEFAULT_INPUT_CHAIN_ACTION,
                hosts_set_name=hosts_set_name,
            )
        else:
            input_chain, input_deps = _build_input_chain(
                iface_match=iface_match,
                metadata_addr=None,
                metadata_port=None,
                dhcp_src_port=546,
                dhcp_dst_port=547,
                ipv6=True,
                default_action=config.DEFAULT_INPUT_CHAIN_ACTION,
                hosts_set_name=hosts_set_name,
            )
        forward_chain, forward_deps = _build_forward_chain(iface_match)

        iptables_updater.rewrite_chains(
            {
                CHAIN_FORWARD: forward_chain,
                CHAIN_INPUT: input_chain
            },
            {
                CHAIN_FORWARD: forward_deps,
                CHAIN_INPUT: input_deps,
            },
            async=False)

        iptables_updater.ensure_rule_inserted(
            "INPUT --jump %s" % CHAIN_INPUT,
            async=False)
        iptables_updater.ensure_rule_inserted(
            "FORWARD --jump %s" % CHAIN_FORWARD,
            async=False)


def rules_to_chain_rewrite_lines(chain_name, rules, ip_version, tag_to_ipset,
                                 on_allow="ACCEPT", on_deny="DROP",
                                 comment_tag=None):
    fragments = []
    for r in rules:
        rule_version = r.get('ip_version')
        if rule_version is None or rule_version == ip_version:
            fragments.extend(rule_to_iptables_fragments(chain_name, r,
                                                        ip_version,
                                                        tag_to_ipset,
                                                        on_allow=on_allow,
                                                        on_deny=on_deny))
    # If we get to the end of the chain without a match, we mark the packet
    # to let the caller know that we haven't accepted the packet.
    fragments.append('--append %s --match comment '
                     '--comment "Mark as not matched" '
                     '--jump MARK --set-mark 1' % chain_name)
    return fragments


def commented_drop_fragment(chain_name, comment):
    comment = comment[:255]  # Limit imposed by iptables.
    assert re.match(r'[\w: ]{,255}', comment), "Invalid comment %r" % comment
    return ('--append %s --jump DROP -m comment --comment "%s"' %
            (chain_name, comment))


def rule_to_iptables_fragments(chain_name, rule, ip_version, tag_to_ipset,
                               on_allow="ACCEPT", on_deny="DROP"):
    """
    Convert a rule dict to a list of iptables fragments suitable to use with
    iptables-restore.

    Most rules result in result list containing one item.

    :param str chain_name: Name of the chain this rule belongs to (used in the
           --append)
    :param dict[str,str|list|int] rule: Rule dict.
    :param str on_allow: iptables action to use when the rule allows traffic.
           For example: "ACCEPT" or "RETURN".
    :param str on_deny: iptables action to use when the rule denies traffic.
           For example: "DROP".
    :return list[str]: iptables --append fragments.
    """

    # Check we've not got any unknown fields.
    unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
    assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

    # Ports are special, we have a limit on the number of ports that can go in
    # one rule so we need to break up rules with a lot of ports into chunks.
    # We take the cross product of the chunks to cover all the combinations.
    # If there are not ports or if there are only a few ports then the cross
    # product ends up with only one entry.
    src_ports = rule.get("src_ports", [])
    dst_ports = rule.get("dst_ports", [])
    src_port_chunks = _split_port_lists(src_ports)
    dst_port_chunks = _split_port_lists(dst_ports)
    rule_copy = dict(rule)  # Only need a shallow copy so we can replace ports.
    try:
        fragments = []
        for src_ports, dst_ports in itertools.product(src_port_chunks,
                                                      dst_port_chunks):
            rule_copy["src_ports"] = src_ports
            rule_copy["dst_ports"] = dst_ports
            frag = _rule_to_iptables_fragment(chain_name, rule_copy, ip_version,
                                              tag_to_ipset,  on_allow=on_allow,
                                              on_deny=on_deny)
            fragments.append(frag)
        return fragments
    except Exception as e:
        # Defensive: isolate failures to parse the rule (which has already
        # passed validation by this point) to this chain.
        _log.exception("Failed to parse rules: %r", e)
        return [commented_drop_fragment(chain_name,
                                        "ERROR failed to parse rules DROP:")]


def _split_port_lists(ports):
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


def _rule_to_iptables_fragment(chain_name, rule, ip_version, tag_to_ipset,
                               on_allow="ACCEPT", on_deny="DROP"):
    """
    Convert a rule dict to an iptables fragment suitable to use with
    iptables-restore.

    :param str chain_name: Name of the chain this rule belongs to (used in the
           --append)
    :param dict[str,str|list|int] rule: Rule dict.
    :param str on_allow: iptables action to use when the rule allows traffic.
           For example: "ACCEPT" or "RETURN".
    :param str on_deny: iptables action to use when the rule denies traffic.
           For example: "DROP".
    :returns list[str]: list of iptables --append fragments.
    """

    # Check we've not got any unknown fields.
    unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
    assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

    # Build up the update in chunks and join them below.
    update_fragments = ["--append", chain_name]
    append = lambda *args: update_fragments.extend(args)

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

        # Port lists/ranges, which we map to multiport. Ignore not just "None"
        # but also an empty list.
        ports_key = dirn + "_ports"
        if ports_key in rule and rule[ports_key]:
            assert proto in ["tcp", "udp"], "Protocol %s not supported with " \
                                            "%s (%s)" % (proto, ports_key, rule)
            ports = ','.join([str(p) for p in rule[ports_key]])
            # multiport only supports 15 ports.  The calling function should
            # have taken care of that.
            num_ports = ports.count(",") + ports.count(":") + 1
            assert num_ports <= 15, "Too many ports (%s)" % ports
            append("--match multiport", "--%s-ports" % direction, ports)

    if rule.get("icmp_type") is not None:
        icmp_type = rule["icmp_type"]
        if icmp_type == 255:
            # Temporary work-around for this issue:
            # https://github.com/Metaswitch/calico/issues/451
            # This exception will be caught by the caller, which will replace
            # this rule with a DROP rule.  That's arguably better than
            # forbidding this case in the validation routine, which would
            # replace the whole chain with a DROP.
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

    # Add the action
    append("--jump", on_allow if rule.get("action", "allow") == "allow"
                              else on_deny)

    return " ".join(str(x) for x in update_fragments)


def _build_input_chain(iface_match, metadata_addr, metadata_port,
                       dhcp_src_port, dhcp_dst_port, ipv6=False,
                       default_action="DROP", hosts_set_name=None):
    """
    Returns a list of rules that should be applied to the felix-INPUT chain.
    :returns Tuple: list of rules and set of deps.
    """
    chain = []

    if hosts_set_name:
        # IP-in-IP enabled, drop any IP-in-IP packets that are not from other
        # Calico hosts.
        _log.info("IPIP enabled, dropping IPIP packets from non-Calico hosts.")
        chain.append(
            "--append %s --protocol ipencap "
            "--match set ! --match-set %s src --jump DROP" %
            (CHAIN_INPUT, hosts_set_name)
        )

    # Optimisation: return immediately if the traffic is not from one of the
    # interfaces we're managing.
    chain.append("--append %s ! --in-interface %s --jump RETURN" %
                 (CHAIN_INPUT, iface_match,))
    deps = set()

    # Allow established connections via the conntrack table.
    chain.append("--append %s --match conntrack "
                 "--ctstate INVALID --jump DROP" % (CHAIN_INPUT,))
    chain.append("--append %s --match conntrack "
                 "--ctstate RELATED,ESTABLISHED --jump ACCEPT" %
                 (CHAIN_INPUT,))

    #  In ipv6 only, there are 6 rules that need to be created first.
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmptype 130
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmptype 131
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmptype 132
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmp router-advertisement
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmp neighbour-solicitation
    #  ACCEPT ipv6-icmp anywhere anywhere ipv6-icmp neighbour-advertisement
    #
    #  These rules are ICMP types 130, 131, 132, 134, 135 and 136.
    if ipv6:
        for icmp_type in ["130", "131", "132", "134", "135", "136"]:
            chain.append("--append %s --jump ACCEPT "
                         "--protocol ipv6-icmp "
                         "--icmpv6-type %s" %
                         (CHAIN_INPUT, icmp_type))

    if metadata_addr is not None:
        _log.info("Metadata address specified, whitelisting metadata service")
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

    if default_action != "DROP":
        # Optimisation: the from-ENDPOINT chain signals acceptance of a packet
        # by RETURNing.  If we're going to drop the packet anyway, don't
        # bother applying the from-ENDPOINT chain.
        _log.info("Default endpoint->host action set to %s, felix will apply"
                  "per-endpoint policy to packets in the INPUT chain.",
                  default_action)
        chain.append(
            "--append %s --jump %s" %
            (CHAIN_INPUT, CHAIN_FROM_ENDPOINT)
        )
        deps.add(CHAIN_FROM_ENDPOINT)

    if default_action != "RETURN":
        # Optimisation: RETURN is the default if the packet reaches the end of
        # the chain so no need to program it.
        chain.append(
            "--append %s --jump %s" % (CHAIN_INPUT, default_action)
        )

    return chain, deps


def _build_forward_chain(iface_match):
    """
    Builds a list of rules that should be applied to the felix-FORWARD
    chain.
    :returns Tuple: list of rules and set of deps.
    """
    forward_chain = [
        "--append %s --in-interface %s --match conntrack "
        "--ctstate INVALID --jump DROP" % (CHAIN_FORWARD, iface_match),
        "--append %s --out-interface %s --match conntrack "
        "--ctstate INVALID --jump DROP" % (CHAIN_FORWARD, iface_match),
        "--append %s --in-interface %s --match conntrack "
        "--ctstate RELATED,ESTABLISHED --jump RETURN" %
        (CHAIN_FORWARD, iface_match),
        "--append %s --out-interface %s --match conntrack "
        "--ctstate RELATED,ESTABLISHED --jump RETURN" %
        (CHAIN_FORWARD, iface_match),
        "--append %s --jump %s --in-interface %s" %
        (CHAIN_FORWARD, CHAIN_FROM_ENDPOINT, iface_match),
        "--append %s --jump %s --out-interface %s" %
        (CHAIN_FORWARD, CHAIN_TO_ENDPOINT, iface_match),
        "--append %s --jump ACCEPT --in-interface %s" %
        (CHAIN_FORWARD, iface_match),
        "--append %s --jump ACCEPT --out-interface %s" %
        (CHAIN_FORWARD, iface_match),
    ]
    return forward_chain, set([CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT])


def interface_to_suffix(config, iface_name):
    suffix = iface_name.replace(config.IFACE_PREFIX, "", 1)
    # The suffix is surely not very long, but make sure.
    suffix = futils.uniquely_shorten(suffix, 16)
    return suffix


def chain_names(endpoint_suffix):
    to_chain_name = (CHAIN_TO_PREFIX + endpoint_suffix)
    from_chain_name = (CHAIN_FROM_PREFIX + endpoint_suffix)
    return to_chain_name, from_chain_name


class UnsupportedICMPType(Exception):
    pass

