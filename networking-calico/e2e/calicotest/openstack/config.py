# -*- coding: utf-8 -*-
# Copyright (c) 2014-2026 Tigera, Inc. All rights reserved.
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
calicotest.openstack.config
~~~~~~~~~~~~

The config submodule contains configuration for calicotest OpenStack tests.
"""
from configparser import Error as ConfigParserError, RawConfigParser
import logging

from calicotest import settings
from calicotest.openstack.compute import Compute
from calicotest.openstack.control import Control

_log = logging.getLogger(__name__)
IPERF_PATH = settings.IPERF_DPKG_PATH
VALID_OS_VALUES = ["Ubuntu"]


class BadLayoutError(Exception):
    """
    Raised when the layout file (settings.LAYOUT_FILE) is missing or
    does not describe a usable rig.
    """


class ClusterLayout(object):
    """
    A class that holds configuration.

    This class provides a useful mapping over the underlying configuration
    file.
    """

    def __init__(self):
        self.filename = settings.LAYOUT_FILE
        self._parser = RawConfigParser()
        if not self._parser.read(self.filename):
            raise BadLayoutError(
                "Could not read cluster layout from %s" % self.filename
            )

        # if a keyfile is needed for connection to the nodes (e.g. on GCE)
        self.keyfile = self._get_optional("DEFAULTS", "keyfile")

        # OS type of deployment.
        self.os_type = self._get_optional("DEFAULTS", "os_type", default="Ubuntu")
        assert self.os_type in VALID_OS_VALUES

        self.test_node_ip = self._get_optional("DEFAULTS", "test_node_ip", default=None)

        #: The control node.
        self.control_node = None
        self.control_node_by_region = {}

        #: A list of compute nodes.
        self.compute_nodes = []
        self.compute_nodes_by_region = {}

        # Log file locations.
        self.felix_log_file = "/var/log/calico/felix.log"
        self.neutron_log_file = "/var/log/neutron/neutron-server.log"
        _log.info("LAYOUT.neutron_log_file is %s", self.neutron_log_file)

        self._populate_nodes()

        self.neutron_host = self._get_optional(
            "DEFAULTS", "neutron_host", default=self.control_node.fqdn
        )
        self.keystone_host = self._get_optional(
            "DEFAULTS", "keystone_host", default=self.control_node.fqdn
        )

    def _get_optional(self, section, attribute, default=None):
        """
        Return an optional attribute value if specified, otherwise return the
        default.

        :param section:   The section containing the attribute
        :param attribute: The attribute name
        :param default:   The default value
        :return:   The specified value, or default.
        """
        if self._parser.has_option(section, attribute):
            return self._parser.get(section, attribute)
        else:
            return default

    def _populate_nodes(self):
        """
        The configuration file contains a list of well-known categories. All
        other categories are machines to be manipulated. Find them and put them
        into the appropriate config variables.
        """
        known_sections = {"DEFAULTS"}
        seen_regions = set()
        for section in self._parser.sections():
            if section in known_sections:
                continue

            # If the section isn't one of the known fixed sections, then it
            # is a node.
            role_name = self._parser.get(section, "role")
            region = self._get_optional(section, "region")
            if role_name.startswith("controller"):
                if region in seen_regions:
                    raise ValueError("Too many control nodes in region %s." % region)
                admin_password = self._get_optional(
                    section, "admin-password", default="abcdef"
                )
                control_node = Control(
                    section,
                    self._parser.get(section, "fqdn"),
                    self._parser.get(section, "username"),
                    self._get_optional(section, "password"),
                    admin_password,
                    keyfile=self.keyfile,
                    ip=self._get_optional(section, "ip"),
                    region=region,
                )

                self.control_node_by_region[region] = control_node
                if self.control_node is None:
                    # Store off the first control node for non-region-aware
                    # tests.
                    self.control_node = control_node
            elif role_name.startswith("compute"):
                node = Compute(
                    section,
                    self._parser.get(section, "fqdn"),
                    self._parser.get(section, "username"),
                    self._get_optional(section, "password"),
                    keyfile=self.keyfile,
                    ip=self._get_optional(section, "ip"),
                    region=region,
                )
                self.compute_nodes_by_region.setdefault(region, []).append(node)
            else:
                raise ValueError("Unknown role %s for %s" % (role_name, section))

        if self.control_node is None:
            raise BadLayoutError("No controller node defined in %s" % self.filename)

        # For non-region-aware tests, make sure the default set of computes
        # matches the default control node.
        self.compute_nodes = self.compute_nodes_by_region[self.control_node.region]


try:
    LAYOUT = ClusterLayout()
except (ConfigParserError, BadLayoutError):
    _log.exception("Hit exception loading the cluster layout")
    LAYOUT = None
