# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Metaswitch Networks
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

# Definition of transport interface for the Calico/OpenStack Plugin

# Standard Python library imports.
import abc
import six


@six.add_metaclass(abc.ABCMeta)
class CalicoTransport(object):
    """Abstract base class for Calico transport implementations."""

    def __init__(self, driver):
        super(CalicoTransport, self).__init__()
        self.driver = driver

    @abc.abstractmethod
    def initialize(self):
        pass                    # pragma: no cover

    @abc.abstractmethod
    def endpoint_created(self, port):
        """Indicate to the transport that an endpoint has been created.

        Args:
          port (dict): OpenStack Neutron dict holding properties of the created
            port, with the following additions.

            (1) port['fixed_ips'][N]['gateway'] set to the gateway IP address
            for the subnet from which the relevant endpoint IP address was
            allocated.

            (2) port['interface_name'] set to the name of the TAP interface
            that OpenStack has created for this endpoint on the compute host.

        """
        pass                    # pragma: no cover

    @abc.abstractmethod
    def endpoint_updated(self, port):
        """Indicate to the transport that an endpoint has been updated.

        Args:
          port (dict): OpenStack Neutron dict holding new properties of the
            updated port, with the following additions.

            (1) port['fixed_ips'][N]['gateway'] set to the gateway IP address
            for the subnet from which the relevant endpoint IP address was
            allocated.

        """
        pass                    # pragma: no cover

    @abc.abstractmethod
    def endpoint_deleted(self, port):
        """Indicate to the transport that an endpoint has been deleted.

        Args:
          port (dict): OpenStack Neutron dict holding properties of the deleted
            port.

        """
        pass                    # pragma: no cover

    @abc.abstractmethod
    def security_group_updated(self, sg):
        """Indicate to the transport that a security group has been updated.

        Args:
          sg (dict): OpenStack Neutron dict holding properties of the updated
            security group, with the following additions.

            (1) sg['members'] set to a dict whose keys are the endpoints
            configured to use that SG, and whose values are the corresponding
            IP addresses.

        """
        pass                    # pragma: no cover
