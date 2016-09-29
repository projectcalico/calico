# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Calico common utilities.
"""
import errno
import netaddr
import netaddr.core
import os
import re

# White-list for the --protocol match criteria.  We allow the guaranteed
# string shortcuts as well as int/string versions of the raw IDs.  We disallow
# 0 because the kernel cannot match on it directly.
KERNEL_PROTOCOLS = set(["tcp", "udp", "icmp", "icmpv6", "sctp", "udplite"])
KERNEL_PROTOCOLS.update(xrange(1, 256))
KERNEL_PROTOCOLS.update(intern(str(p)) for p in xrange(1, 256))

# Protocols that support a port match in iptables.  We allow the name and
# protocol number.
KERNEL_PORT_PROTOCOLS = set([
    "tcp", 6, "6",
    "udp", 17, "17",
    "udplite", 136, "136",
    "sctp", 132, "132",
    "dccp", 33, "33",
])

NEGATABLE_MATCH_KEYS = [
    "protocol",
    "src_net",
    "src_tag",
    "src_selector",
    "src_ports",
    "dst_net",
    "dst_tag",
    "dst_selector",
    "dst_ports",
    "icmp_type",
    "icmp_code",
]

# Valid keys for a rule JSON dict.
KNOWN_RULE_KEYS = set(
    [
        "action",
        "ip_version",
        "log_prefix",
    ] +
    NEGATABLE_MATCH_KEYS +
    ["!%s" % k for k in NEGATABLE_MATCH_KEYS]
)

# Valid actions to see in a rule.
KNOWN_ACTIONS = set(["allow", "deny", "next-tier", "log"])

# Regex that matches only names with valid characters in them. The list of
# valid characters is the same for endpoints, profiles, and tags.
VALID_ID_RE = re.compile(r'^[a-zA-Z0-9_\.\-]+$')

INVALID_LOG_KEY_CHARS = re.compile(r'[^a-zA-Z0-9_:-]')


def validate_cidr(cidr, version):
    """validate_cidr

    Validates that a CIDR is valid. Returns true if valid, false if
    not. Version can be "4", "6", None for "IPv4", "IPv6", or "either"
    respectively.
    """
    try:
        ip = netaddr.IPNetwork(cidr, version=version)
        assert ip
        return True
    except (netaddr.core.AddrFormatError, ValueError, TypeError):
        return False


def canonicalise_cidr(cidr, version):
    assert cidr is not None
    nw = netaddr.IPNetwork(cidr, version=version)
    return intern(str(nw))


def mkdir_p(path):
    """http://stackoverflow.com/a/600612/190597 (tzot)"""
    try:
        os.makedirs(path, exist_ok=True)  # Python>3.2
    except TypeError:
        try:
            os.makedirs(path)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise


class ValidationFailed(Exception):
    """Class used for data validation exceptions."""
    pass


def validate_profile(profile_id, profile):
    """validate_profile

    Validates and normalises the given profile dictionary.

    As side effects to the input dict:

    * Fields that are set to None in rules are removed completely.

    Once this routine has returned successfully, we know that all
    required fields are present and have valid values.

    :param str profile_id: The ID of the profile, which is also validated.
    :param profile: The profile dict.  For example,
          {"inbound_rules": [...], "outbound_rules": [...]}
    :raises ValidationFailed
    """
    # The code below relies on the top-level object to be a dict.  Check
    # that first.
    if not isinstance(profile, dict):
        raise ValidationFailed("Expected profile %r to be a dict, not %r." %
                               (profile_id, profile))

    issues = []
    if not VALID_ID_RE.match(profile_id):
        issues.append("Invalid profile ID '%r'." % profile_id)

    _validate_rules(profile, issues)

    if issues:
        raise ValidationFailed(" ".join(issues))


def _validate_rules(rules_dict, issues):
    """Validates and normalises the given rules dictionary.

    As side effects to the input dict:

    * Fields that are set to None in rules are removed completely.

    Once this routine has returned successfully, we know that all
    required fields are present and have valid values.

    :param dict rules_dict: profile dict as read from etcd
    :param list issues: Updated with any issues discovered.
    """
    for dirn in ("inbound_rules", "outbound_rules"):
        if dirn not in rules_dict:
            rules_dict[dirn] = []
            continue

        if not isinstance(rules_dict[dirn], list):
            issues.append("Expected rules[%s] to be a list." % dirn)
            continue

        for rule in rules_dict[dirn]:
            if not isinstance(rule, dict):
                issues.append("Rule should be a dict: %r" % rule)
                break

            for key, value in rule.items():
                if value is None:
                    del rule[key]

            ip_version = rule.get('ip_version')
            if ip_version is not None and ip_version not in (4, 6):
                # Bad IP version prevents further validation
                issues.append("Invalid ip_version in rule %s." % rule)
                continue

            for neg_pfx in ("", "!"):
                _validate_rule_match_criteria(rule, issues, neg_pfx)

            unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
            if unknown_keys:
                issues.append("Rule contains unknown keys: %s." % unknown_keys)


def _validate_rule_match_criteria(rule, issues, neg_pfx):
    """Validates and canonicalises a rule's match criteria.

    Each call validates either the negated or non-negated match criteria.
    I.e. the ones with "!" prefixed or not.

    :param rule: The dict for the individual rule.  Protocols and IPs are
           normalised.
    :param list[str] issues: List of issues found.  This method appends any
           issues it finds to the list.
    :param str neg_pfx: The negation prefix, "" for positive matches or "!"
           for negative.
    """
    # Absolutely all fields are optional, but some have valid and
    # invalid values.
    assert neg_pfx in ("", "!")

    # Explicitly get the non-negated protocol; even negated matches on port
    # or ICMP values require the protocol to be specified.
    protocol = rule.get("protocol")

    # Check the (possibly negated) profile.
    protocol_key = neg_pfx + 'protocol'
    maybe_neg_proto = rule.get(protocol_key)
    if maybe_neg_proto is not None and maybe_neg_proto not in KERNEL_PROTOCOLS:
        issues.append("Invalid %s %s in rule %s" %
                      (protocol_key, maybe_neg_proto, rule))
    elif maybe_neg_proto is not None:
        maybe_neg_proto = intern(str(maybe_neg_proto))
        rule[protocol_key] = str(maybe_neg_proto)

    ip_version = rule.get('ip_version')
    if ip_version == 4 and protocol == "icmpv6":
        issues.append("Using icmpv6 with IPv4 in rule %s." % rule)
    if ip_version == 6 and protocol == "icmp":
        issues.append("Using icmp with IPv6 in rule %s." % rule)

    for tag_type in (neg_pfx + 'src_tag', neg_pfx + 'dst_tag'):
        tag = rule.get(tag_type)
        if tag is None:
            continue
        if not VALID_ID_RE.match(tag):
            issues.append("Invalid %s: %r." % (tag_type, tag))

    # The Calico driver for OpenStack is not expected to generate
    # profiles that use selectors.
    for sel_type in (neg_pfx + 'src_selector', neg_pfx + 'dst_selector'):
        sel_str = rule.get(sel_type)
        if sel_str is not None:
            # sel_type was present.
            raise ValidationFailed(
                "Calico/OpenStack is not expected to generate " +
                "profiles that use selectors"
            )

    if "log_prefix" in rule:
        log_pfx = rule["log_prefix"]
        if not isinstance(log_pfx, basestring):
            issues.append("Log prefix should be a string")
        else:
            # Sanitize the log prefix.  iptables length limit is 29 chars but
            # we add ": " to the end in the iptables generator.
            rule["log_prefix"] = INVALID_LOG_KEY_CHARS.sub("_", log_pfx)[:27]

    for key in (neg_pfx + "src_net", neg_pfx + "dst_net"):
        network = rule.get(key)
        if (network is not None and
                not validate_cidr(rule[key], ip_version)):
            issues.append("Invalid CIDR (version %s) in rule %s." %
                          (ip_version, rule))
        elif network is not None:
            rule[key] = canonicalise_cidr(network, ip_version)
    for key in (neg_pfx + "src_ports", neg_pfx + "dst_ports"):
        ports = rule.get(key)
        if (ports is not None and
                not isinstance(ports, list)):
            issues.append("Expected ports to be a list in rule %s."
                          % rule)
            continue

        if ports is not None:
            if protocol not in KERNEL_PORT_PROTOCOLS:
                issues.append("%s is not allowed for protocol %s in "
                              "rule %s" % (key, protocol, rule))
            for port in ports:
                error = _validate_rule_port(port)
                if error:
                    issues.append("Invalid port %s (%s) in rule %s." %
                                  (port, error, rule))

    action = rule.get(neg_pfx + 'action')
    if (action is not None and
            action not in KNOWN_ACTIONS):
        issues.append("Invalid action in rule %s." % rule)

    icmp_type = rule.get(neg_pfx + 'icmp_type')
    if icmp_type is not None:
        if not isinstance(icmp_type, int):
            issues.append("ICMP type is not an integer in rule %s." %
                          rule)
        elif not 0 <= icmp_type <= 255:
            issues.append("ICMP type is out of range in rule %s." %
                          rule)
    icmp_code = rule.get(neg_pfx + "icmp_code")
    if icmp_code is not None:
        if not isinstance(icmp_code, int):
            issues.append("ICMP code is not an integer in rule %s." %
                          rule)
        elif not 0 <= icmp_code <= 255:
            issues.append("ICMP code is out of range.")
        if icmp_type is None:
            # ICMP code without ICMP type not supported by iptables;
            # firewall against that.
            issues.append("ICMP code specified without ICMP type.")


def _validate_rule_port(port):
    """Validates that any value in a port list really is valid.

    Valid values are an integer port, or a string range separated by a colon.

    :param port: the port, which is validated for type
    :returns: None or an error string if invalid
    """
    if isinstance(port, int):
        if port < 0 or port > 65535:
            return "integer out of range"
        return None

    # If not an integer, must be format N:M, i.e. a port range.
    try:
        fields = port.split(":")
    except AttributeError:
        return "neither integer nor string"

    if not len(fields) == 2:
        return "range unparseable"

    try:
        start = int(fields.pop(0))
        end = int(fields.pop(0))
    except ValueError:
        return "range invalid"

    if start >= end or start < 0 or end > 65535:
        return "range invalid"

    return None
