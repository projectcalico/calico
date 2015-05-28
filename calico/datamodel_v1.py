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
calico.datamodel
~~~~~~~~~~~~~~~~

Shared etcd data-model definitions for version 1 of the data model.

This file is versioned.  The idea is that only back-compatible changes
should be made to this file and non-back-compatible changes should be
made in a new copy of the file with revved version suffix.  That allows
us to maintain multiple copies of the data model in parallel during
migrations.
"""
from collections import namedtuple
import logging
import re

_log = logging.getLogger(__name__)

# All Calico data is stored under this path.
ROOT_DIR = "/calico"

# OpenStack data is stored under this path.
OPENSTACK_DIR = ROOT_DIR + "/openstack"

# Data that flows from orchestrator to felix is stored under a versioned
# sub-tree.
VERSION_DIR = ROOT_DIR + "/v1"
# Global ready flag.  Stores 'true' or 'false'.
READY_KEY = VERSION_DIR + "/Ready"
# Global config (directory).
CONFIG_DIR = VERSION_DIR + '/config'
HOST_DIR = VERSION_DIR + '/host'
POLICY_DIR = VERSION_DIR + '/policy'
PROFILE_DIR = POLICY_DIR + "/profile"

# Key used for leader election by Neutron mechanism drivers.
NEUTRON_ELECTION_KEY = OPENSTACK_DIR + '/neutron_election'

# Regex to match profile rules, capturing the profile ID in capture group
# "profile_id".
RULES_KEY_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)/rules')
# Regex to match profile tags, capturing the profile ID in capture group
# "profile_id".
TAGS_KEY_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)/tags')
# Regex to match endpoints, captures "hostname" and "endpoint_id".
ENDPOINT_KEY_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/'
    r'workload/'
    r'(?P<orchestrator>[^/]+)/'
    r'(?P<workload_id>[^/]+)/'
    r'endpoint/(?P<endpoint_id>[^/]+)')


def dir_for_host(hostname):
    return HOST_DIR+ "/%s" % hostname


def dir_for_per_host_config(hostname):
    return dir_for_host(hostname) + "/config"


def key_for_endpoint(host, orchestrator, workload_id, endpoint_id):
    return (HOST_DIR + "/%s/workload/%s/%s/endpoint/%s" %
            (host, orchestrator, workload_id, endpoint_id))


def key_for_profile(profile_id):
    return PROFILE_DIR + "/" + profile_id


def key_for_profile_rules(profile_id):
    return PROFILE_DIR + "/%s/rules" % profile_id


def key_for_profile_tags(profile_id):
    return PROFILE_DIR + "/%s/tags" % profile_id


def key_for_config(config_name):
    return CONFIG_DIR + "/%s" % config_name


def get_profile_id_for_profile_dir(key):
    """
    :param str key: etcd key.
    :returns The profile ID if this is a profile dir or None if not.
    """
    key = key.rstrip('/')
    if "/" not in key:
        return None
    prefix, final_node = key.rsplit("/", 1)
    return final_node if prefix == PROFILE_DIR else None


class EndpointId(namedtuple("EndpointId", ["host", "orchestrator",
                                           "workload", "endpoint"])):
    def __str__(self):
        return self.__class__.__name__ + ("<%s/%s/%s/%s>" % self)
