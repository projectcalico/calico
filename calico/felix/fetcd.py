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
from socket import timeout as SocketTimeout
from etcd import (EtcdException, EtcdClusterIdChanged, EtcdKeyNotFound,
                  EtcdEventIndexCleared)
import etcd
import httplib
import json
import logging
import gevent
from urllib3 import Timeout
import urllib3.exceptions
from urllib3.exceptions import ReadTimeoutError, ConnectTimeoutError

from calico import common
from calico.common import ValidationFailed, KNOWN_RULE_KEYS
from calico.datamodel_v1 import (VERSION_DIR, READY_KEY, CONFIG_DIR,
                                 RULES_KEY_RE, TAGS_KEY_RE, ENDPOINT_KEY_RE,
                                 dir_for_per_host_config,
                                 get_profile_id_for_profile_dir, dir_for_host,
                                 PROFILE_DIR, HOST_DIR)
from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)


RETRY_DELAY = 5

# If we see an unhandled event (e.g. a directory deletion) for keys in any of
# these prefixes, we'll abort our polling and resync.
PREFIXES_TO_RESYNC_ON_CHANGE = [
    READY_KEY,
    PROFILE_DIR,
    HOST_DIR,
]


class EtcdWatcher(Actor):
    def __init__(self, config):
        super(EtcdWatcher, self).__init__()
        self.config = config
        self.client = None
        self.my_config_dir = dir_for_per_host_config(self.config.HOSTNAME)

    @actor_message()
    def load_config(self):
        _log.info("Waiting for etcd to be ready and for config to be present.")
        configured = False
        while not configured:
            self._reconnect()
            self.wait_for_ready()
            try:
                config_dict = self._load_config_dict()
            except (EtcdKeyNotFound, EtcdException):
                _log.exception("Failed to read config.  Will retry.")
                gevent.sleep(RETRY_DELAY)
                continue

            self.config.update_config(config_dict)
            common.complete_logging(self.config.LOGFILE,
                                    self.config.LOGLEVFILE,
                                    self.config.LOGLEVSYS,
                                    self.config.LOGLEVSCR)
            configured = True

    @actor_message()
    def wait_for_ready(self):
        _log.info("Waiting for etcd to be ready...")
        ready = False
        while not ready:
            try:
                db_ready = self.client.read(READY_KEY,
                                            timeout=10).value
            except EtcdKeyNotFound:
                _log.warn("Ready flag not present in etcd, waiting...")
                db_ready = "false"
            except EtcdException:
                _log.exception("Failed to retrieve ready flag from etcd, "
                               "waiting...")
                db_ready = "false"

            if db_ready == "true":
                _log.info("etcd is ready.")
                ready = True
            else:
                _log.info("etcd not ready.  Will retry.")
                gevent.sleep(RETRY_DELAY)
                continue

    def _reconnect(self, copy_cluster_id=True):
        _log.info("(Re)connecting to etcd...")
        etcd_addr = self.config.ETCD_ADDR
        if ":" in etcd_addr:
            host, port = etcd_addr.split(":")
            port = int(port)
        else:
            host = etcd_addr
            port = 4001
        if self.client and copy_cluster_id:
            old_cluster_id = self.client.expected_cluster_id
            _log.info("Old etcd cluster ID was %s.", old_cluster_id)
        else:
            old_cluster_id = None
        self.client = etcd.Client(host=host, port=port,
                                  expected_cluster_id=old_cluster_id)

    @actor_message()
    def watch_etcd(self, update_splitter):
        """
        Loads the snapshot from etcd and then monitors etcd for changes.
        Posts events to the UpdateSplitter.

        :returns: Does not return.
        """
        while True:
            _log.info("Reconnecting and loading snapshot from etcd...")
            self._reconnect(copy_cluster_id=False)
            self.wait_for_ready()

            # Load initial dump from etcd.  First just get all the endpoints
            # and profiles by id.  The response contains a generation ID
            # allowing us to then start polling for updates without missing
            # any.
            initial_dump = self.client.read(VERSION_DIR, recursive=True)
            _log.info("Loaded snapshot from etcd cluster %s, parsing it...",
                      self.client.expected_cluster_id)
            rules_by_id = {}
            tags_by_id = {}
            endpoints_by_id = {}
            still_ready = False
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

                # Double-check the flag hasn't changed since we read it before.
                if child.key == READY_KEY:
                    if child.value == "true":
                        still_ready = True
                    else:
                        _log.warning("Aborting resync because ready flag was"
                                     "unset since we read it.")
                        continue

            if not still_ready:
                _log.warn("Aborting resync; ready flag no longer present.")
                continue

            # Actually apply the snapshot. This does not return anything, but
            # just sends the relevant messages to the relevant threads to make
            # all the processing occur.
            _log.info("Snapshot parsed, passing to update splitter")
            update_splitter.apply_snapshot(rules_by_id,
                                           tags_by_id,
                                           endpoints_by_id,
                                           async=False)

            # These read only objects are no longer required, so tidy them up.
            del rules_by_id
            del tags_by_id
            del endpoints_by_id

            # On first call, the etcd_index seems to be the high-water mark
            # for the data returned whereas the modified index just tells us
            # when the key was modified.
            _log.info("Starting polling for updates from etcd.  Initial etcd "
                      "index: %s.", initial_dump.etcd_index)
            next_etcd_index = initial_dump.etcd_index + 1
            del initial_dump
            continue_polling = True
            while continue_polling:
                response = None
                try:
                    _log.debug("About to wait for etcd update %s",
                               next_etcd_index)
                    response = self.client.read(VERSION_DIR,
                                                wait=True,
                                                waitIndex=next_etcd_index,
                                                recursive=True,
                                                timeout=Timeout(connect=10,
                                                                read=90),
                                                check_cluster_uuid=True)
                    _log.debug("etcd response: %r", response)
                except (ReadTimeoutError, SocketTimeout) as e:
                    # This is expected when we're doing a poll and nothing
                    # happened. socket timeout doesn't seem to be caught by
                    # urllib3 1.7.1.  Simply reconnect.
                    _log.debug("Read from etcd timed out (%r), retrying.", e)
                    # Force a reconnect to ensure urllib3 doesn't recycle the
                    # connection.  (We were seeing this with urllib3 1.7.1.)
                    self._reconnect()
                except (ConnectTimeoutError,
                        urllib3.exceptions.HTTPError,
                        httplib.HTTPException):
                    _log.warning("Low-level HTTP error, reconnecting to "
                                 "etcd.", exc_info=True)
                    self._reconnect()
                except (EtcdClusterIdChanged, EtcdEventIndexCleared) as e:
                    _log.warning("Out of sync with etcd (%r).  Reconnecting "
                                 "for full sync.", e)
                    continue_polling = False
                except EtcdException as e:
                    # Sadly, python-etcd doesn't have a dedicated exception
                    # for the "no more machines in cluster" error. Parse the
                    # message:
                    msg = (e.message or "unknown").lower()
                    if "no more machines" in msg:
                        # This error comes from python-etcd when it can't
                        # connect to any servers.  When we retry, it should
                        # reconnect.
                        # TODO: We should probably limit retries here and die
                        # That'd recover from errors caused by resource
                        # exhaustion/leaks.
                        _log.error("Connection to etcd failed, will retry.")
                    else:
                        # Assume any other errors are fatal to our poll and
                        # do a full resync.
                        _log.exception("Unknown etcd error %r; doing resync.",
                                       e.message)
                        continue_polling = False
                    # TODO: should we do a backoff here?
                    gevent.sleep(1)
                    self._reconnect()
                except:
                    _log.exception("Unexpected exception during etcd poll")
                    raise

                if not response:
                    _log.debug("Failed to get a response from etcd.")
                    continue

                # Since we're polling on a subtree, we can't just increment
                # the index, we have to look at the modifiedIndex to spot if
                # we've skipped a lot of updates.
                next_etcd_index = max(next_etcd_index,
                                      response.modifiedIndex) + 1

                if response.action == "delete":
                    # Handle expected directory deletions by faking events for
                    # child nodes.
                    profile_id = get_profile_id_for_profile_dir(response.key)
                    if profile_id:
                        _log.info("Delete for whole profile %s", profile_id)
                        update_splitter.on_rules_update(profile_id, None,
                                                        async=False)
                        update_splitter.on_tags_update(profile_id, None,
                                                       async=False)
                        continue
                    # TODO: Do we need to handle workload deletions?

                profile_id, rules = parse_if_rules(response)
                if profile_id:
                    _log.info("Scheduling profile update %s", profile_id)
                    update_splitter.on_rules_update(profile_id, rules,
                                                    async=False)
                    continue
                profile_id, tags = parse_if_tags(response)
                if profile_id:
                    _log.info("Scheduling tags update %s", profile_id)
                    update_splitter.on_tags_update(profile_id, tags,
                                                   async=False)
                    continue
                endpoint_id, endpoint = parse_if_endpoint(self.config,
                                                          response)
                if endpoint_id:
                    _log.info("Scheduling endpoint update %s", endpoint_id)
                    update_splitter.on_endpoint_update(endpoint_id, endpoint,
                                                       async=False)
                    continue

                if response.key == READY_KEY:
                    if response.value != "true":
                        _log.warning("DB became unready, triggering a resync")
                        continue_polling = False
                    continue

                _log.debug("Response action: %s, key: %s",
                           response.action, response.key)
                if (response.action not in ("set", "create") and
                        any((response.key.startswith(pfx) for pfx in
                             PREFIXES_TO_RESYNC_ON_CHANGE))):
                    # Catch deletions of whole directories or other operations
                    # that we're not expecting.
                    _log.warning("Unexpected event: %s; triggering resync.",
                                 response)
                    continue_polling = False
                if response.key.startswith(CONFIG_DIR):
                    _log.warning("Global config changed but we don't "
                                 "yet support dynamic config: %s",
                                 response)
                if response.key.startswith(self.my_config_dir):
                    _log.warning("Config for this felix changed but we don't "
                                 "yet support dynamic config: %s",
                                 response)

    def _load_config_dict(self):
        """
        Load configuration detail for this host from etcd.

        Merges global and per-host config.

        :returns: a dictionary of key to parameters
        :raises EtcdException: if a read from etcd fails.
        """

        # Load the global config, if this fails, we let the exception
        # propagate.
        global_cfg = self.client.read(CONFIG_DIR)
        config_dict = {}
        _update_config_dict(config_dict, global_cfg)
        # Load the overrides for this host, if present.
        try:
            host_cfg = self.client.read(self.my_config_dir)
        except EtcdKeyNotFound:
            _log.info("No configuration overrides for this node")
        else:
            _update_config_dict(config_dict, host_cfg)

        return config_dict


def _update_config_dict(config_dict, cfg_node):
    """
    Updates the config dict provided from the given etcd node, which
    should point at a config directory.
    """
    for child in cfg_node.children:
        _log.info("Config parameter: %s=%s", child.key, child.value)
        key = child.key.rsplit("/").pop()
        value = str(child.value)
        config_dict[key] = value
    return config_dict


# Intern JSON keys as we load them to reduce occupancy.
def intern_dict(d):
    return dict((intern(str(k)), v) for k, v in d.iteritems())
json_decoder = json.JSONDecoder(object_hook=intern_dict)


def parse_if_endpoint(config, etcd_node):
    m = ENDPOINT_KEY_RE.match(etcd_node.key)
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
                common.validate_endpoint(config, endpoint)
            except ValidationFailed as e:
                _log.warning("Validation failed for endpoint %s, treating as "
                             "missing: %s", endpoint_id, e.message)
                return endpoint_id, None
            endpoint["host"] = hostname
            endpoint["id"] = endpoint_id
            _log.debug("Found endpoint : %s", endpoint)
        return endpoint_id, endpoint
    return None, None


def parse_if_rules(etcd_node):
    m = RULES_KEY_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = json_decoder.decode(etcd_node.value)
            rules["id"] = profile_id
            try:
                common.validate_rules(rules)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s rules: %s",
                               profile_id, rules)
                return profile_id, None

        _log.debug("Found rules for profile %s : %s", profile_id, rules)

        return profile_id, rules
    return None, None


def parse_if_tags(etcd_node):
    m = TAGS_KEY_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = json_decoder.decode(etcd_node.value)
            try:
                common.validate_tags(tags)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s tags : %s",
                               profile_id, tags)
                return profile_id, None

        _log.debug("Found tags for profile %s : %s", profile_id, tags)

        return profile_id, tags
    return None, None
