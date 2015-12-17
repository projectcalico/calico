# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from util import configure_logging
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.datastore_errors import MultipleEndpointsMatch
from pycalico.util import validate_characters

# Use the same logger as calico_cni.
_log = logging.getLogger("calico_cni")


class BasePolicyDriver(object):
    """
    Abstract base class of a CNI Policy Driver.

    The CNI Policy Driver is responsible for applying network policy to
    networked containers and creating/applying Calico profiles to Calico
    endpoints.
    """
    def __init__(self):

        self._client = DatastoreClient()
        """
        DatastoreClient for access to the Calico datastore.
        """

        self.profile_name = None
        """
        Name of profile for attach to endpoint. Must be set in init function
        of subclass.
        """

    def apply_profile(self, endpoint):
        """Sets a profile for the networked container on the given endpoint.

        Create a profile if it is not yet created.

        :param endpoint:
        :return: None
        """
        assert self.profile_name, "No profile name set."
        if not self._client.profile_exists(self.profile_name):
            # If the profile doesn't exist, create it.
            _log.info("Creating new profile '%s'", self.profile_name)
            rules = self.generate_rules()
            self._client.create_profile(self.profile_name, rules)

        # Check if the profile has already been applied.
        if self.profile_name in endpoint.profile_ids:
            _log.warning("Endpoint already in profile %s", 
                         self.profile_name)
            return

        # Set the default profile on this pod's Calico endpoint.
        _log.info("Appending profile '%s' to endpoint %s",
                  self.profile_name, endpoint.endpoint_id)
        try:
            self._client.append_profiles_to_endpoint(
                    profile_names=[self.profile_name],
                    endpoint_id=endpoint.endpoint_id
            )
        except (KeyError, MultipleEndpointsMatch), e:
            _log.exception("Failed to apply profile to endpoint %s: %s",
                           endpoint.name, e.message)
            raise ApplyProfileError(e.message)

    def remove_profile(self):
        """Remove the profile if there are no endpoints attached.

        :return: None
        """
        raise NotImplementedError("Must implement method in subclass")

    def generate_rules(self):
        """Generates Calico Rules

        :rtype: Calico Rules datatype or None
        :return: rules - contains inbound and outbound policy rules; None
        uses default rules
        """
        raise NotImplementedError("Must implement method in subclass")


class DefaultPolicyDriver(BasePolicyDriver):
    """
    Implements default network policy for a generic CNI plugin.
    """
    def __init__(self, network_name):
        BasePolicyDriver.__init__(self)
        if not validate_characters(network_name):
            raise ValueError("Invalid characters detected in the given network "
                             "name, %s. Only letters a-z, numbers 0-9, and "
                             "symbols _.- are supported.", network_name)
        self.profile_name = network_name

    def remove_profile(self):
        """Right now this function is a no-op.

        Need to think more about how to handle the race condition that exists
        between removing a profile and creating a new one of the same name.

        For now we'll leak profiles in Calico datastore.

        :return: None
        """
        _log.info("Not removing profile %s. Clean up manually if desired",
                  self.profile_name)

    def generate_rules(self):
        """Generates rules for a default CNI plugin.

        The default rules for a generic CNI plugin is to allow ingress traffic
        from containers in the same network and allow all egress traffic.

        :return: None - use default rules
        """
        return None


class KubernetesDefaultPolicyDriver(DefaultPolicyDriver):
    """
    Implements default network policy for a Kubernetes container manager.

    The different between this an the DefaultPolicyDriver is that this 
    engine creates profiles which allow all incoming traffic.
    """
    def generate_rules(self):
        """Generates default rules for a Kubernetes container manager.

        The default rules for Kubernetes is to allow all ingress and egress
        traffic.

        :rtype: A Calico Rules object
        :return: rules - allow all ingress and egress traffic
        """
        allow = Rule(action="allow")
        rules = Rules(id=self.profile_name,
                      inbound_rules=[allow],
                      outbound_rules=[allow])
        return rules

class ApplyProfileError(Exception):
    """
    Attempting to apply a profile to an endpoint that does not exist.
    """
    pass
