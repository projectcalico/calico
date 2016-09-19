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
calico.common
~~~~~~~~~~~~

Calico common utilities.
"""
import errno
import logging
import logging.handlers
import numbers
import os
import re
import sys
from types import StringTypes

import netaddr
import netaddr.core
from netaddr.strategy import eui48
from calico.felix.futils import IPV4, IP_TYPE_TO_VERSION

from calico.datamodel_v1 import TieredPolicyId, LABEL_CHARS
from calico.felix.selectors import parse_selector, BadSelector

_log = logging.getLogger(__name__)

AGENT_TYPE_CALICO = 'Calico agent'

FORMAT_STRING = '%(asctime)s [%(levelname)s][%(process)s/%(thread)d] %(name)s %(lineno)d: %(message)s'
# Used "tid", which we swap for the greenlet ID, instead of "thread"
FORMAT_STRING_GEVENT = '%(asctime)s [%(levelname)s][%(process)s/%(tid)d] %(name)s %(lineno)d: %(message)s'

# This format string deliberately uses two different styles of format
# specifier. The %()s form is used by the logging module: the {} form is used
# by the code in this module. This allows us to dynamically generate the format
# string used by the logger.
SYSLOG_FORMAT_STRING = '{excname}[%(process)s]: %(module)s@%(lineno)d %(message)s'

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

# Regex for validating the names of labels, which need to be rich enough to
# allow for Kubernetes implementation, for example.
VALID_LABEL_NAME_RE = re.compile(r'^[%s]+$' % re.escape(LABEL_CHARS))

VALID_LINUX_IFACE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,15}$')

INVALID_LOG_KEY_CHARS = re.compile(r'[^a-zA-Z0-9_:-]')

# Not that thorough: we don't care if it's a valid CIDR, only that it doesn't
# have anything malicious in it.
VALID_IPAM_POOL_ID_RE = re.compile(r'^[0-9\.:a-fA-F\-]{1,43}$')
EXPECTED_IPAM_POOL_KEYS = set(["cidr", "masquerade"])

INFINITY = float("inf")


def validate_port(port):
    """
    Validates that a port is valid. Returns true if valid, false if not.
    """
    try:
        port_int = int(port)
        if port_int <= 0 or port_int > 65535:
            return False
        else:
            return True

    except ValueError:
        return False


def validate_ip_addr(addr, version=None):
    """
    Validates that an IP address is valid. Returns true if valid, false if
    not. Version can be "4", "6", None for "IPv4", "IPv6", or "either"
    respectively.
    """
    if version == 4:
        return netaddr.valid_ipv4(addr)
    elif version == 6:
        return netaddr.valid_ipv6(addr)
    else:
        return netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)


def canonicalise_ip(addr, version):
    if addr is None:
        return None
    ip = netaddr.IPAddress(addr, version=version)
    return intern(str(ip))


def validate_cidr(cidr, version):
    """
    Validates that a CIDR is valid. Returns true if valid, false if
    not. Version can be "4", "6", None for "IPv4", "IPv6", or "either"
    respectively.
    """
    try:
        ip = netaddr.IPNetwork(cidr, version=version)
        return True
    except (netaddr.core.AddrFormatError, ValueError, TypeError):
        return False


def canonicalise_cidr(cidr, version):
    if cidr is None:
        return None
    nw = netaddr.IPNetwork(cidr, version=version)
    return intern(str(nw))


def canonicalise_mac(mac):
    # Use the Unix dialect, which uses ':' for its separator instead of
    # '-'.  This fits best with what iptables is expecting.
    eui = netaddr.EUI(mac, dialect=eui48.mac_unix)
    return str(eui)


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
            else: raise


def default_logging(gevent_in_use=True, syslog_executable_name=None):
    """
    Sets up the Calico default logging, with default severities.

    Our default logging consists of:

    - setting the log level of the root logger to DEBUG (a safe initial value)
    - attaching a SysLog handler with no formatter (log to syslog), ERROR level
      only
    - attaching a StreamHandler with the Calico formatter, to log to stdout,
      with ERROR level

    This default explicitly excludes adding logging to file. This is because
    working out what file to log to requires reading the configuration file,
    and doing that may cause errors that we want to log! To add a file logger,
    call :meth:`complete_logging() <calico.common.complete_logging>` after
    this function has been called.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    executable_name = syslog_executable_name or os.path.basename(sys.argv[0])
    syslog_format = SYSLOG_FORMAT_STRING.format(excname=executable_name)
    syslog_formatter = logging.Formatter(syslog_format)
    if os.path.exists("/dev/log"):
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    else:
        # Probably unit tests running on windows.
        syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setLevel(logging.ERROR)
    syslog_handler.setFormatter(syslog_formatter)

    root_logger.addHandler(syslog_handler)

    format_string = FORMAT_STRING_GEVENT if gevent_in_use else FORMAT_STRING
    file_formatter = logging.Formatter(format_string)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.ERROR)
    stream_handler.setFormatter(file_formatter)
    if gevent_in_use:
        from geventutils import GreenletFilter
        stream_handler.addFilter(GreenletFilter())
    root_logger.addHandler(stream_handler)


def complete_logging(logfile=None,
                     file_level=logging.DEBUG,
                     syslog_level=logging.ERROR,
                     stream_level=logging.ERROR,
                     gevent_in_use=True):
    """
    Updates the logging configuration based on learned configuration.

    The purpose of this function is to update the previously set logging
    configuration such that we can start logging to file. This is done in a
    separate step to the initial logging configuration in order to ensure that
    logging is available as early in execution as possible, i.e. before the
    config file has been parsed.

    This function must only be called once, after
    :meth:`default_logging() <calico.common.default_logging>`
    has been called.

    The xyz_level parameters may be a valid logging level DEBUG/INFO/... or
    None to disable that log entirely.  Note: the config module supports
    using the string "none" in the configuration to disable logging.
    """
    root_logger = logging.getLogger()

    # If default_logging got called already, we'll have some loggers in place.
    # Update their levels.
    file_handler = None
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.handlers.SysLogHandler):
            if syslog_level is None:
                root_logger.removeHandler(handler)
            else:
                handler.setLevel(syslog_level)
        elif isinstance(handler, logging.StreamHandler):
            if stream_level is None:
                root_logger.removeHandler(handler)
            else:
                handler.setLevel(stream_level)
        elif isinstance(handler, logging.handlers.WatchedFileHandler):
            file_handler = handler
            if file_level is None:
                root_logger.removeHandler(handler)
            else:
                handler.setLevel(file_level)

    # If we've been given a log file, log to file as well.
    if logfile and file_level is not None:
        if not file_handler:
            mkdir_p(os.path.dirname(logfile))
            format_string = (FORMAT_STRING_GEVENT if gevent_in_use
                             else FORMAT_STRING)
            formatter = logging.Formatter(format_string)
            file_handler = logging.handlers.WatchedFileHandler(logfile)
            if gevent_in_use:
                from geventutils import GreenletFilter
                file_handler.addFilter(GreenletFilter())
            file_handler.setLevel(file_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

    # Optimization: disable all logging below the minimum level that we care
    # about.  The global "disable" setting is the first thing that gets checked
    # in the logging framework so it's the fastest way to disable logging.
    levels = [file_level, syslog_level, stream_level]
    # Map None to something greater than the highest logging level.
    levels = [l if l is not None else logging.CRITICAL + 1 for l in levels]
    min_log_level = min(levels)
    logging.disable(min_log_level - 1)

    _log.info("Logging initialized")


class ValidationFailed(Exception):
    """
    Class used for data validation exceptions.
    """
    pass


def nat_key(ip_type):
    if ip_type in [IPV4, IP_TYPE_TO_VERSION[IPV4]]:
        return "ipv4_nat"
    else:
        return "ipv6_nat"


def validate_endpoint(config, combined_id, endpoint):
    """Validate a workload endpoint.

    :param config: configuration structure
    :param combined_id: WloadEndpointId object
    :param endpoint: endpoint dictionary as read from etcd
    :raises ValidationFailed
    """
    issues = _validate_endpoint_common(config, combined_id, endpoint)

    # Workload endpoint-specific validation.
    if "name" not in endpoint:
        issues.append("Missing 'name' field.")
    elif (isinstance(endpoint['name'], StringTypes)
            and combined_id.host == config.HOSTNAME
            and not any(endpoint["name"].startswith(prefix)
                        for prefix in config.IFACE_PREFIX)):
        # Only test the interface for local endpoints - remote hosts may have
        # a different interface prefix.
        issues.append("Interface %r does not start with any of %r." %
                      (endpoint["name"], config.IFACE_PREFIX))
    if "state" not in endpoint:
        issues.append("Missing 'state' field.")
    elif endpoint["state"] not in ("active", "inactive"):
        issues.append("Expected 'state' to be one of active/inactive.")

    if "expected_ipv4_addrs" in endpoint or "expected_ipv6_addrs" in endpoint:
        issues.append("Expected IP addresses not supported for workload "
                      "endpoints.")

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_host_endpoint(config, combined_id, endpoint):
    """Validate a host endpoint.

    :param config: configuration structure
    :param combined_id: HostEndpointId object
    :param endpoint: endpoint dictionary as read from etcd
    :raises ValidationFailed
    """
    issues = _validate_endpoint_common(config, combined_id, endpoint)

    # Forbid workload endpoint fields that we don't support.
    for version in (4, 6):
        nets = "ipv%d_nets" % version
        if nets in endpoint:
            issues.append("Field '%s' not supported for host endpoints" %
                          nets)
        gw_key = "ipv%d_gateway" % version
        if gw_key in endpoint:
            issues.append("Field '%s' not supported for host endpoints" %
                          gw_key)
        nat_maps = nat_key(version)
        if nat_maps in endpoint:
            issues.append("Field '%s' not supported for host endpoints" %
                          nat_maps)
    if "state" in endpoint:
        issues.append("'state' field not supported for host endpoints")
    if "mac" in endpoint:
        issues.append("'mac' field not supported for host endpoints")

    # Host endpoint-specific validation. We need either a name for the
    # interface or at least one expected IP address.
    expected_ip_present = (endpoint.get("expected_ipv4_addrs") or
                           endpoint.get("expected_ipv6_addrs"))
    name_present = "name" in endpoint
    if not name_present and not expected_ip_present:
        issues.append("'name' or 'expected_ipvx_addr' must be present.")

    # Check the expected addr fields are valid IPs, if present.
    for key, version in [("expected_ipv4_addrs", 4),
                         ("expected_ipv6_addrs", 6)]:
        if key in endpoint:
            if not isinstance(endpoint[key], list):
                issues.append("%r should be a list" % key)
            else:
                for ip in endpoint[key]:
                    if not validate_ip_addr(ip, version):
                        issues.append("'%s' should be a valid IP, not %r." %
                                      (key, ip))
                    else:
                        endpoint[key] = [canonicalise_ip(ip, version)
                                         for ip in endpoint[key]]

    if issues:
        raise ValidationFailed(" ".join(issues))


def _validate_endpoint_common(config, combined_id, endpoint):
    """
    Ensures that the supplied endpoint is valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    Has the side-effect of putting IP and MAC addresses in canonical form in
    the input dict.

    :param config: configuration structure
    :param combined_id: EndpointId object
    :param endpoint: endpoint dictionary as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(endpoint, dict):
        raise ValidationFailed("Expected endpoint to be a dict.")

    if not VALID_ID_RE.match(combined_id.endpoint):
        issues.append("Invalid endpoint ID '%r'." % combined_id.endpoint)

    if "name" in endpoint:
        if not isinstance(endpoint["name"], StringTypes):
            issues.append("Expected 'name' to be a string; got %r." %
                          endpoint["name"])
        elif not VALID_LINUX_IFACE_NAME_RE.match(endpoint["name"]):
            issues.append("'name' must be a valid interface name.")

    if "mac" in endpoint:
        if not netaddr.valid_mac(endpoint["mac"]):
            issues.append("Invalid MAC address.")
        else:
            endpoint["mac"] = canonicalise_mac(endpoint.get("mac"))

    if "profile_id" in endpoint:
        if "profile_ids" not in endpoint:
            endpoint["profile_ids"] = [endpoint["profile_id"]]
        del endpoint["profile_id"]

    if "profile_ids" not in endpoint:
        endpoint["profile_ids"] = []
    else:
        for value in endpoint["profile_ids"]:
            if not isinstance(value, StringTypes):
                issues.append("Expected profile IDs to be strings.")
                break

            if not VALID_ID_RE.match(value):
                issues.append("Invalid profile ID '%r'." % value)

    if "labels" in endpoint:
        _validate_label_dict(issues, endpoint["labels"])

    for version in (4, 6):
        nets = "ipv%d_nets" % version
        if nets in endpoint:
            canonical_nws = []
            nets_list = endpoint.get(nets, [])
            if not isinstance(nets_list, list):
                issues.append("%s should be a list." % nets)
            else:
                for ip in nets_list:
                    if not validate_cidr(ip, version):
                        issues.append("IP address %r is not a valid "
                                      "IPv%d CIDR." % (ip, version))
                        break
                    else:
                        canonical_nws.append(canonicalise_cidr(ip, version))
                endpoint[nets] = canonical_nws

        n_key = nat_key(version)
        nat_maps = endpoint.get(n_key, None)
        if nat_maps is not None:
            if isinstance(nat_maps, list):
                canonical_nm = []
                for nat_map in nat_maps:
                    canonical = {}
                    for t in "int", "ext":
                        canonical[t] = None
                        ip = nat_map.get("%s_ip" % t, None)
                        if ip:
                            if validate_ip_addr(ip, version):
                                canonical[t] = canonicalise_ip(ip, version)
                            else:
                                issues.append("%s_ip (%r) is not a valid IPv%d"
                                              " address." % (t, ip, version))
                        else:
                            issues.append("%s_ip was not specified a %s entry."
                                          % (t, n_key))
                    if canonical["int"] and canonical["ext"]:
                        canonical_nm.append({"int_ip": canonical["int"],
                                             "ext_ip": canonical["ext"]})
                endpoint[n_key] = canonical_nm

                for nat_map in canonical_nm:
                    if version == 4:
                        nm = "/32"
                    else:
                        nm = "/128"
                    int_ip_nm = nat_map["int_ip"] + nm
                    # At this point these have all been canonicalized, so we
                    # should be able to do a strict string comparison.
                    if int_ip_nm not in endpoint.get(nets, []):
                        issues.append("int_ip %s is not listed in %s." %
                                      (int_ip_nm, nets))
            else:
                issues.append("%s should be a list." % n_key)

        gw_key = "ipv%d_gateway" % version
        try:
            gw_str = endpoint[gw_key]
            if gw_str is not None and not validate_ip_addr(gw_str,
                                                           version):
                issues.append("%s is not a valid IPv%d gateway address." %
                              (gw_key, version))
            else:
                endpoint[gw_key] = canonicalise_ip(gw_str, version)
        except KeyError:
            pass
    return issues


def validate_tier_data(tier, data):
    issues = []
    if not VALID_ID_RE.match(tier):
        issues.append("Invalid profile_id '%r'." % tier)

    if not isinstance(data, dict):
        raise ValidationFailed("Expected tier data to be a dict not %r" % data)

    if "order" not in data or data["order"] == "default":
        data["order"] = INFINITY
    else:
        order = data["order"]
        if not isinstance(order, numbers.Number):
            issues.append('Tier data "order" field should be number or '
                          '"default"')

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_policy(policy_id, policy):
    """
    Validates and normalises the given policy dictionary.

    As side effects to the input dict:

    * Fields that are set to None in rules are removed completely.
    * Selectors are replaced with SelectorExpression objects.  Parsing now
      ensures that the selectors are valid and ensures that equal selectors
      compare and hash equally.  For example: "a == 'b'" and "a=='b'" are
      different strings that parse to the same selector.

    Once this routine has returned successfully, we know that all
    required fields are present and have valid values.

    :param TieredPolicyId policy_id: The ID of the profile, which is also
           validated.
    :param policy: The profile dict.  For example,
           {"inbound_rules": [...],
            "outbound_rules": [...],
            "selector": "foo == 'bar'",
            "order": 123}
    :raises ValidationFailed
    """
    # The code below relies on the top-level object to be a dict.  Check
    # that first.
    if not isinstance(policy, dict):
        raise ValidationFailed("Expected policy '%s' to be a dict, not %r." %
                               (policy_id, policy))

    issues = []

    for part in policy_id.tier, policy_id.policy_id:
        if not VALID_ID_RE.match(part):
            issues.append("Invalid profile ID '%r'." % policy_id)

    _validate_rules(policy, issues)

    if "selector" in policy:
        try:
            selector = parse_selector(policy["selector"])
        except BadSelector:
            issues.append("Failed to parse selector %s" % policy["selector"])
        else:
            policy["selector"] = selector
    else:
        issues.append("Profile missing required selector field")

    if "order" not in policy or policy["order"] == "default":
        policy["order"] = INFINITY
    else:
        if not isinstance(policy["order"], numbers.Number):
            issues.append('Order should be a number, or "default", not %s' %
                          policy["order"])

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_profile(profile_id, profile):
    """
    Validates and normalises the given profile dictionary.

    As side effects to the input dict:

    * Fields that are set to None in rules are removed completely.
    * Selectors are replaced with SelectorExpression objects.  Parsing now
      ensures that the selectors are valid and ensures that equal selectors
      compare and hash equally.  For example: "a == 'b'" and "a=='b'" are
      different strings that parse to the same selector.

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
    """
    Validates and normalises the given rules dictionary.

    As side effects to the input dict:

    * Fields that are set to None in rules are removed completely.
    * Selectors are replaced with SelectorExpression objects.  Parsing now
      ensures that the selectors are valid and ensures that equal selectors
      compare and hash equally.  For example: "a == 'b'" and "a=='b'" are
      different strings that parse to the same selector.

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

    :param rule: The dict for the individual rule.  If this contains selectors,
           they are replaced with parsed versions.  Protocols and IPs are
           also normalised.
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

    # For selectors, we replace the value with the parsed selector.
    # This avoids having to re-parse it later and it ensures that
    # equivalent selectors compare equal.
    for sel_type in (neg_pfx + 'src_selector', neg_pfx + 'dst_selector'):
        sel_str = rule.get(sel_type)
        if sel_str is None:
            # sel_type wasn't present.
            continue
        try:
            sel = parse_selector(sel_str)
        except BadSelector:
            issues.append("Invalid %s: %r" % (sel_type, sel_str))
        else:
            rule[sel_type] = sel

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
                error = validate_rule_port(port)
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


def validate_rule_port(port):
    """
    Validates that any value in a port list really is valid.
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


def validate_tags(profile_id, tags):
    """
    Ensures that the supplied tags are valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    :param profile_id: profile_id as read from etcd
    :param tags: tag set as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not VALID_ID_RE.match(profile_id):
        issues.append("Invalid profile_id '%r'." % profile_id)

    if not isinstance(tags, list):
        issues.append("Expected tags to be a list.")
    else:
        for tag in tags:
            if not isinstance(tag, StringTypes):
                issues.append("Expected tag '%s' to be a string." % tag)
                break

            if not VALID_ID_RE.match(tag):
                issues.append("Invalid tag '%r'." % tag)

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_labels(profile_id, labels):
    issues = []

    if not VALID_ID_RE.match(profile_id):
        issues.append("Invalid profile_id %r." % profile_id)
    _validate_label_dict(issues, labels)
    if issues:
        raise ValidationFailed(" ".join(issues))


def _validate_label_dict(issues, labels):
    if not isinstance(labels, dict):
        issues.append("Expected labels to be a dict, not %r." % labels)
    else:
        for label_name, value in labels.iteritems():
            if not VALID_LABEL_NAME_RE.match(label_name):
                issues.append("Invalid label name %r." % label_name)
            if isinstance(value, basestring):
                continue
            else:
                issues.append("Invalid label value %r." % value)


def validate_ipam_pool(pool_id, pool, ip_version):
    """
    Validates and canonicalises an IPAM pool dict.  Removes any fields that
    it doesn't know about.

    Modifies the dict in-place.
    """
    if not isinstance(pool, dict):
        raise ValidationFailed("Pool should be a dict")

    # Remove any keys that we're not expecting.  Stops unvalidated data from
    # slipping through.  We ignore other keys since this structure is used
    # by calicoctl for its own purposes too.
    keys_to_remove = set()
    for key in pool:
        if key not in EXPECTED_IPAM_POOL_KEYS:
            keys_to_remove.add(key)
    for key in keys_to_remove:
        pool.pop(key)

    issues = []
    if "cidr" not in pool:
        # CIDR is mandatory.
        issues.append("'cidr' field is missing")
    else:
        cidr = pool["cidr"]
        if cidr is None or not validate_cidr(cidr, ip_version):
            issues.append("Invalid CIDR: %r" % cidr)
        else:
            pool["cidr"] = canonicalise_cidr(cidr, ip_version)

    if not isinstance(pool.get("masquerade", False), bool):
        issues.append("Invalid 'masquerade' field: %r" % pool["masquerade"])

    if not VALID_IPAM_POOL_ID_RE.match(pool_id):
        issues.append("Invalid pool ID: %r" % pool)

    if issues:
        raise ValidationFailed(','.join(issues))
