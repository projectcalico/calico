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
from subprocess import CalledProcessError
from calico.felix import futils
import re

_log = logging.getLogger(__name__)


# Chain names
CHAIN_PREROUTING = "felix-PREROUTING"
CHAIN_INPUT = "felix-INPUT"
CHAIN_FORWARD = "felix-FORWARD"
CHAIN_TO_ENDPOINT = "felix-TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = "felix-FROM-ENDPOINT"
CHAIN_TO_PREFIX = "felix-to-"
CHAIN_FROM_PREFIX = "felix-from-"
CHAIN_PROFILE_PREFIX = "felix-p-"


# Valid keys for a rule JSON dict.
KNOWN_RULE_KEYS = set([
    "action",
    "protocol",
    "src_net",
    "src_tag",
    "src_ports",
    "dst_net",
    "dst_tag",
    "dst_ports",
    "icmp_type",
])


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


def install_global_rules(config, v4_updater, v6_updater):
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
    v4_updater.rewrite_chains("nat", {CHAIN_PREROUTING: nat_pr}, {},
                              async=False)

    v4_updater.ensure_rule_inserted("nat",
                                    "PREROUTING --jump %s" % CHAIN_PREROUTING,
                                    async=False)

    # Now the filter table. This needs to have calico-filter-FORWARD and
    # calico-filter-INPUT chains, which we must create before adding any
    # rules that send to them.
    for iptables_updater in [v4_updater, v6_updater]:
        iptables_updater.rewrite_chains(
            "filter",
            {
                CHAIN_FORWARD: [
                    "--append %s --jump %s --in-interface %s" %
                        (CHAIN_FORWARD, CHAIN_FROM_ENDPOINT, iface_match),
                    "--append %s --jump %s --out-interface %s" %
                        (CHAIN_FORWARD, CHAIN_TO_ENDPOINT, iface_match),
                    "--append %s --jump ACCEPT --in-interface %s" %
                        (CHAIN_FORWARD, iface_match),
                    "--append %s --jump ACCEPT --out-interface %s" %
                        (CHAIN_FORWARD, iface_match),
                ],
                CHAIN_INPUT: [
                    "--append %s --jump %s --in-interface %s" %
                        (CHAIN_INPUT, CHAIN_FROM_ENDPOINT, iface_match),
                    "--append %s --jump ACCEPT --in-interface %s" %
                        (CHAIN_INPUT, iface_match),
                ]
            },
            {
                CHAIN_FORWARD: set([CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT]),
                CHAIN_INPUT: set([CHAIN_FROM_ENDPOINT]),
            },
            async=False)
        iptables_updater.ensure_rule_inserted(
            "filter",
            "INPUT --jump %s" % CHAIN_INPUT,
            async=False)
        iptables_updater.ensure_rule_inserted(
            "filter",
            "FORWARD --jump %s" % CHAIN_FORWARD,
            async=False)


def rules_to_chain_rewrite_lines(chain_name, rules, ip_version, tag_to_ipset,
                                 on_allow="ACCEPT", on_deny="DROP"):
    try:
        fragments = []
        for r in rules:
            rule_version = r.get('ip_version')
            if rule_version is None or rule_version == ip_version:
                fragments.append(rule_to_iptables_fragment(chain_name, r,
                                                           ip_version,
                                                           tag_to_ipset,
                                                           on_allow=on_allow,
                                                           on_deny=on_deny))
        fragments.append(commented_drop_fragment(chain_name,
                                                 "Default DROP rule:"))
        return fragments
    except Exception:
        _log.exception("Failed to convert rules to fragments: %s.  Will DROP!",
                       rules)
        return [commented_drop_fragment(chain_name,
                                        "ERROR failed to parse rules DROP:")]


def commented_drop_fragment(chain_name, comment):
    assert re.match(r'[\w: ]{,256}', comment), "Invalid comment %r" % comment
    return ('--append %s --jump DROP -m comment --comment "%s"' %
            (chain_name, comment))


def rule_to_iptables_fragment(chain_name, rule, ip_version, tag_to_ipset,
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
    :return str: iptables --append fragment.
    """

    # Check we've not got any unknown fields.
    unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
    assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

    # Build up the update in chunks and join them below.
    update_fragments = ["--append", chain_name]
    append = lambda *args: update_fragments.extend(args)

    proto = None
    if "protocol" in rule:
        proto = rule["protocol"]
        assert proto in ["tcp", "udp", "icmp", "icmpv6"]
        append("--protocol", proto)

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
            # multiport only supports 15 ports.
            # TODO: return multiple rules if we have more than one port
            assert ports.count(",") + ports.count(":") < 15, "Too many ports"
            append("--match multiport", "--%s-ports" % direction, ports)

    if "icmp_type" in rule and rule["icmp_type"] is not None:
        icmp_type = rule["icmp_type"]
        assert isinstance(icmp_type, int), "ICMP type should be an int"
        if proto == "icmp" and ip_version == 4:
            append("--match icmp", "--icmp-type", rule["icmp_type"])
        elif ip_version == 6:
            assert proto == "icmpv6"
            # Note variant spelling of icmp[v]6
            append("--match icmp6", "--icmpv6-type", rule["icmp_type"])

    # Add the action
    append("--jump", on_allow if rule.get("action", "allow") == "allow"
                              else on_deny)

    return " ".join(str(x) for x in update_fragments)
