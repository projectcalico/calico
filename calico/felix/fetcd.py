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
felix.fetcd
~~~~~~~~~~~~

Etcd polling functions.
"""
from etcd import EtcdException
import etcd
import itertools
import json
import logging
import re
from types import StringTypes
from urllib3.exceptions import ReadTimeoutError

from calico import common
from calico.felix.futils import logging_exceptions
from calico.felix.actor import Actor, actor_event

_log = logging.getLogger(__name__)


# etcd path regexes
RULES_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/rules')
TAGS_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/tags')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/.+/endpoint/(?P<endpoint_id>[^/]+)')


class ValidationFailed(Exception):
    pass


class EtcdWatcher(Actor):
    def __init__(self, config, update_splitter):
        super(EtcdWatcher, self).__init__()
        self.update_splitter = update_splitter
        self.config = config

    # TODO: PLW surely we don't need logging_exceptions here? If we do, don't we
    # need it on all actor events?
    @actor_event
    @logging_exceptions
    def watch_etcd(self):
        """
        Loads the snapshot from etcd and then monitors etcd for changes.
        Posts events to the UpdateSplitter.

        Intended to be used as a greenlet.  Intended to be restarted if
        it raises an exception.

        :returns: Does not return.
        :raises EtcdException: if a read from etcd fails and we may fall out of
                sync.
        """
        while True:
            client = etcd.Client('localhost', self.config.ETCD_PORT)

            # TODO handle GR flag and missing /calico/ node.

            # Load initial dump from etcd.  First just get all the endpoints and
            # profiles by id.  The response contains a generation ID allowing us
            # to then start polling for updates without missing any.
            initial_dump = client.read("/calico/", recursive=True)
            rules_by_id = {}
            tags_by_id = {}
            endpoints_by_id = {}
            for child in initial_dump.children:
                profile_id, rules = parse_if_rules(child)
                if profile_id:
                    rules_by_id[profile_id] = rules
                    continue
                profile_id, tags = parse_if_tags(child)
                if profile_id:
                    tags_by_id[profile_id] = tags
                    continue
                endpoint_id, endpoint = parse_if_endpoint(self.config, child)
                if endpoint_id and endpoint:
                    endpoints_by_id[endpoint_id] = endpoint
                    continue

            # Actually apply the snapshot. This does not return anything, but
            # just sends the relevant messages to the relevant threads to make
            # all the processing occur.
            self.update_splitter.apply_snapshot(rules_by_id,
                                                tags_by_id,
                                                endpoints_by_id)

            # These read only objects are no longer required, so tidy them up.
            del rules_by_id
            del tags_by_id
            del endpoints_by_id

            # On first call, the etcd_index seems to be the high-water mark for the
            # data returned whereas the modified index just tells us when the key
            # was modified.
            _log.info("Initial etcd index: %s; modifiedIndex: %s",
                      initial_dump.etcd_index, initial_dump.modifiedIndex)
            next_etcd_index = initial_dump.etcd_index + 1
            del initial_dump
            continue_polling = True
            while continue_polling:
                try:
                    _log.debug("About to wait for etcd update %s", next_etcd_index)
                    response = client.read("/calico/",
                                           wait=True,
                                           waitIndex=next_etcd_index,
                                           recursive=True,
                                           timeout=0)
                    _log.debug("etcd response: %r", response)
                except ReadTimeoutError:
                    _log.warning("Read from etcd timed out, retrying.")
                    # TODO: We are timing out 60 seconds after the initial
                    # read, then again 60 seconds after that, for no reason I
                    # can really see. However, a timeout of 0 is probably wrong
                    # if that does not reestablish connections
                    # periodically. Needs a bit more thought.
                    continue
                except EtcdException:
                    _log.exception("Failed to read from etcd. wait_index=%s",
                                   next_etcd_index)
                    raise
                # Defensive, the etcd_index returned on subsequent requests is the
                # one that we waited on and the modifiedIndex is the index at
                # which the key's value was changed. Just in case there's a corner
                # case where we get an old modifiedIndex, make sure we always
                # increase the index.
                next_etcd_index = max(response.modifiedIndex, next_etcd_index + 1)

                # TODO: regex parsing getting messy.
                profile_id, rules = parse_if_rules(response)
                if profile_id:
                    _log.info("Scheduling profile update %s", profile_id)
                    self.update_splitter.on_rules_update(profile_id, rules)
                    continue
                profile_id, tags = parse_if_tags(response)
                if profile_id:
                    _log.info("Scheduling profile update %s", profile_id)
                    self.update_splitter.on_tags_update(profile_id, tags)
                    continue
                endpoint_id, endpoint = parse_if_endpoint(self.config, response)
                if endpoint_id:
                    _log.info("Scheduling endpoint update %s", endpoint_id)
                    self.update_splitter.on_endpoint_update(endpoint_id, endpoint)
                    continue

                _log.debug("Response action: %s, key: %s",
                           response.action, response.key)
                if response.action not in ("set", "create"):
                    # FIXME: this check is over-broad.
                    # It's purpose is to catch deletions of whole directories
                    # or other operations that we're not expecting.
                    _log.warning("Unexpected action %s to %s; triggering "
                                 "resync.", response.action, response.key)
                    continue_polling = False


# Intern JSON keys as we load them to reduce occupancy.
def intern_dict(d):
    return dict((intern(str(k)), v) for k, v in d.iteritems())
json_decoder = json.JSONDecoder(object_hook=intern_dict)


def parse_if_endpoint(config, etcd_node):
    m = ENDPOINT_RE.match(etcd_node.key)
    if m:
        # Got an endpoint.
        endpoint_id = m.group("endpoint_id")
        if etcd_node.action == "delete":
            endpoint = None
            _log.debug("Found deleted endpoint %s", endpoint_id)
        else:
            hostname = m.group("hostname")
            endpoint = json_decoder.decode(etcd_node.value)
            try:
                validate_endpoint(config, endpoint)
            except ValidationFailed as e:
                _log.warning("Validation failed for endpoint %s, treating as "
                             "missing: %s", endpoint_id, e.message)
                return endpoint_id, None
            endpoint["host"] = hostname
            endpoint["id"] = endpoint_id
            _log.debug("Found endpoint : %s", endpoint)
        return endpoint_id, endpoint
    return None, None


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

    for field in ["name", "mac", "profile_id"]:
        if field not in endpoint:
            issues.append("Missing '%s' field." % field)
        elif not isinstance(endpoint[field], StringTypes):
            issues.append("Expected '%s' to be a string; got %r." %
                          (field, endpoint[field]))

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
                if not common.validate_cidr(ip, version):
                    issues.append("IP address %r is not a valid IPv%d CIDR." %
                                  (ip, version))
                    break

        gw_key = "ipv%d_gateway" % version
        try:
            gw_str = endpoint[gw_key]
            if gw_str is not None and not common.validate_ip_addr(gw_str,
                                                                  version):
                issues.append("%s is not a valid IPv%d gateway address." %
                              (gw_key, version))
        except KeyError:
            pass

    if issues:
        raise ValidationFailed(" ".join(issues))


def parse_if_rules(etcd_node):
    m = RULES_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = json_decoder.decode(etcd_node.value)
            rules["id"] = profile_id
            try:
                validate_rules(rules)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s rules: %s",
                               profile_id, rules)
                return profile_id, None

        _log.debug("Found rules for profile %s : %s", profile_id, rules)

        return profile_id, rules
    return None, None


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
                    not common.validate_cidr(rule[key], ip_version)):
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
            #TODO: firewall the icmp_type too

    if issues:
        raise ValidationFailed(" ".join(issues))


def validate_rule_port(port):
    """
    Validates that any value in a port list really is valid.
    Valid values are an integer port, or a string range separated by a colon.

    :param port: the port, which is validated for type
    :return str: None or an error string if invalid
    """
    if isinstance(port, int):
        if port < 1 or port > 65535:
            return "integer out of range"
        return None

    if isinstance(port, str):
        # Format N:M, i.e. a port range.
        fields = port.split(":")
        if not len(fields) == 2:
            return "range unparseable"
        start = int(fields.pop(0))
        end = int(fields.pop(0))
        if start >= end or start < 1 or end > 65535:
            return "range invalid"
        return None

    return "neither integer nor string"


def parse_if_tags(etcd_node):
    m = TAGS_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = json_decoder.decode(etcd_node.value)
            try:
                validate_tags(tags)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s tags : %s",
                               profile_id, tags)
                return profile_id, None

        _log.debug("Found tags for profile %s : %s", profile_id, tags)

        return profile_id, tags
    return None, None


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


def load_config(host, port):
    """
    TODO: Add watching of the config, probably not required for MVP.

    Load configuration detail for this host from etcd.
    :returns: a dictionary of key to paarameters
    :raises EtcdException: if a read from etcd fails and we may fall out of
            sync.
    """
    client = etcd.Client(port=port)

    config_dict = {}

    # Load initial dump from etcd.  First just get all the endpoints and
    # profiles by id.  The response contains a generation ID allowing us
    # to then start polling for updates without missing any.
    global_cfg = client.read("/calico/config/")
    host_cfg = client.read("/calico/host/%s/config/" % host)

    for child in itertools.chain(global_cfg.children, host_cfg.children):
        _log.info("Got config parameter : %s=%s", child.key, str(child.value))
        key = child.key.rsplit("/").pop()
        value = str(child.value)
        config_dict[key] = value

    return config_dict
