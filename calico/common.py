# -*- coding: utf-8 -*-

# Copyright (c) 2014, 2015 Metaswitch Networks
# All Rights Reserved.
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
import gevent
import gevent.local
import itertools
import logging
import logging.handlers
import netaddr
import netaddr.core
import os
import sys
from types import StringTypes

_log = logging.getLogger(__name__)

AGENT_TYPE_CALICO = 'Calico agent'
FORMAT_STRING = '%(asctime)s [%(levelname)s][%(process)s/%(tid)d] %(name)s %(lineno)d: %(message)s'

# This format string deliberately uses two different styles of format
# specifier. The %()s form is used by the logging module: the {} form is used
# by the code in this module. This allows us to dynamically generate the format
# string used by the logger.
SYSLOG_FORMAT_STRING = '{excname}[%(process)s]: %(module)s@%(lineno)d %(message)s'

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
    "icmp_code",
    "ip_version",
])

tid_storage = gevent.local.local()
tid_counter = itertools.count()
# Ought to do itertools.count(start=1), but python 2.6 does not support it.
tid_counter.next()

def greenlet_id():
    """
    Returns an integer greenlet ID.
    itertools.count() is atomic, if the internet is correct.
    http://stackoverflow.com/questions/23547604/python-counter-atomic-increment
    """
    try:
        tid = tid_storage.tid
    except:
        tid = tid_counter.next()
        tid_storage.tid = tid
    return tid


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


def validate_ip_addr(addr, version):
    """
    Validates that an IP address is valid. Returns true if valid, false if
    not. Version can be "4", "6", None for "IPv4", "IPv6", or "either"
    respectively.
    """
    try:
        ip = netaddr.IPAddress(addr, version=version)
        return True
    except (netaddr.core.AddrFormatError, ValueError, TypeError):
        return False


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


def mkdir_p(path):
    """http://stackoverflow.com/a/600612/190597 (tzot)"""
    try:
        os.makedirs(path, exist_ok=True)  # Python>3.2
    except TypeError:
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise

class GreenletFilter(logging.Filter):
    def filter(self, record):
        record.tid = greenlet_id()
        return True

def default_logging():
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

    executable_name = os.path.basename(sys.argv[0])
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

    file_formatter = logging.Formatter(FORMAT_STRING)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.ERROR)
    stream_handler.setFormatter(file_formatter)
    stream_handler.addFilter(GreenletFilter())
    root_logger.addHandler(stream_handler)


def complete_logging(logfile=None,
                     file_level=logging.DEBUG,
                     syslog_level=logging.ERROR,
                     stream_level=logging.ERROR):
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
        elif isinstance(handler, logging.handlers.TimedRotatingFileHandler):
            file_handler = handler
            if file_level is None:
                root_logger.removeHandler(handler)
            else:
                handler.setLevel(file_level)

    # If we've been given a log file, log to file as well.
    if logfile and file_level is not None:
        if not file_handler:
            mkdir_p(os.path.dirname(logfile))
            formatter = logging.Formatter(FORMAT_STRING)
            file_handler = logging.handlers.TimedRotatingFileHandler(
                logfile, when="D", backupCount=10
            )
            file_handler.addFilter(GreenletFilter())
            file_handler.setLevel(file_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

    _log.info("Logging initialized")


class ValidationFailed(Exception):
    """
    Class used for data validation exceptions.
    """
    pass


def validate_endpoint(config, endpoint):
    """
    Ensures that the supplied endpoint is valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    :param config: configuration structure
    :param endpoint: endpoint dictionary as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(endpoint, dict):
        raise ValidationFailed("Expected endpoint to be a dict.")

    if "state" not in endpoint:
        issues.append("Missing 'state' field.")
    elif endpoint["state"] not in ("active", "inactive"):
        issues.append("Expected 'state' to be one of active/inactive.")

    for field in ["name", "mac"]:
        if field not in endpoint:
            issues.append("Missing '%s' field." % field)
        elif not isinstance(endpoint[field], StringTypes):
            issues.append("Expected '%s' to be a string; got %r." %
                          (field, endpoint[field]))

    if "profile_id" in endpoint:
        if "profile_ids" not in endpoint:
            endpoint["profile_ids"] = [endpoint["profile_id"]]
        del endpoint["profile_id"]

    if "profile_ids" not in endpoint:
        issues.append("Missing 'profile_id(s)' field.")
    else:
        for value in endpoint["profile_ids"]:
            if not isinstance(value, StringTypes):
                issues.append("Expected profile IDs to be strings.")
                break

    if "name" in endpoint:
        if not endpoint["name"].startswith(config.IFACE_PREFIX):
            issues.append("Interface %r does not start with %r." %
                          (endpoint["name"], config.IFACE_PREFIX))

    for version in (4, 6):
        nets = "ipv%d_nets" % version
        if nets not in endpoint:
            issues.append("Missing network %s." % nets)
        else:
            for ip in endpoint.get(nets, []):
                if not validate_cidr(ip, version):
                    issues.append("IP address %r is not a valid IPv%d CIDR." %
                                  (ip, version))
                    break

        gw_key = "ipv%d_gateway" % version
        try:
            gw_str = endpoint[gw_key]
            if gw_str is not None and not validate_ip_addr(gw_str,
                                                           version):
                issues.append("%s is not a valid IPv%d gateway address." %
                              (gw_key, version))
        except KeyError:
            pass

    if issues:
        raise ValidationFailed(" ".join(issues))

def validate_rules(rules):
    """
    Ensures that the supplied rules are valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    :param rules: rules list as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(rules, dict):
        raise ValidationFailed("Expected rules to be a dict.")

    for dirn in ("inbound_rules", "outbound_rules"):
        if dirn not in rules:
            issues.append("No %s in rules." % dirn)
            continue

        if not isinstance(rules[dirn], list):
            issues.append("Expected rules[%s] to be a dict." % dirn)
            continue

        for rule in rules[dirn]:
            # Absolutely all fields are optional, but some have valid and
            # invalid values.
            protocol = rule.get('protocol')
            if (protocol is not None and
                not protocol in [ "tcp", "udp", "icmp", "icmpv6" ]):
                    issues.append("Invalid protocol in rule %s." % rule)

            ip_version = rule.get('ip_version')
            if (ip_version is not None and
                not ip_version in [ 4, 6 ]):
                # Bad IP version prevents further validation
                issues.append("Invalid ip_version in rule %s." % rule)
                continue

            if ip_version == 4 and protocol == "icmpv6":
                issues.append("Using icmpv6 with IPv4 in rule %s." % rule)
            if ip_version == 6 and protocol == "icmp":
                issues.append("Using icmp with IPv6 in rule %s." % rule)

            # TODO: Validate that src_tag and dst_tag contain only valid characters.

            for key in ("src_net", "dst_net"):
                network = rule.get(key)
                if (network is not None and
                    not validate_cidr(rule[key], ip_version)):
                    issues.append("Invalid CIDR (version %s) in rule %s." %
                                  (ip_version, rule))

            for key in ("src_ports", "dst_ports"):
                ports = rule.get(key)
                if (ports is not None and
                    not isinstance(ports, list)):
                    issues.append("Expected ports to be a list in rule %s."
                                  % rule)
                    continue

                if ports is not None:
                    for port in ports:
                        error = validate_rule_port(port)
                        if error:
                            issues.append("Invalid port %s (%s) in rule %s." %
                                          (port, error, rule))

            action = rule.get('action')
            if (action is not None and
                    action not in ("allow", "deny")):
                issues.append("Invalid action in rule %s." % rule)

            icmp_type = rule.get('icmp_type')
            if icmp_type is not None:
                if not 0 <= icmp_type <= 255:
                    issues.append("ICMP type is out of range.")
            icmp_code = rule.get("icmp_code")
            if icmp_code is not None:
                if not 0 <= icmp_code <= 255:
                    issues.append("ICMP code is out of range.")
                if icmp_type is None:
                    # TODO: ICMP code without ICMP type not supported by iptables
                    # Firewall against that for now.
                    issues.append("ICMP code specified without ICMP type.")

            unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
            if unknown_keys:
                issues.append("Rule contains unknown keys: %s." % unknown_keys)

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_rule_port(port):
    """
    Validates that any value in a port list really is valid.
    Valid values are an integer port, or a string range separated by a colon.

    :param port: the port, which is validated for type
    :returns: None or an error string if invalid
    """
    if isinstance(port, int):
        if port < 1 or port > 65535:
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

    if start >= end or start < 1 or end > 65535:
        return "range invalid"

    return None


def validate_tags(tags):
    """
    Ensures that the supplied tags are valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    :param tags: tag set as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(tags, list):
        issues.append("Expected tags to be a list.")
    else:
        for tag in tags:
            if not isinstance(tag, StringTypes):
                issues.append("Expected tag '%s' to be a string." % tag)
                break

    if issues:
        raise ValidationFailed(" ".join(issues))
