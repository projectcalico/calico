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

import os
import sys
import json
import logging
import requests
from calico_cni.util import print_cni_error
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.datastore_errors import MultipleEndpointsMatch
from pycalico.util import validate_characters

from calico_cni.constants import *
import calico_cni.policy_parser

# Use the same logger as calico_cni.
_log = logging.getLogger("calico_cni")


class DefaultPolicyDriver(object):
    """
    Implements default network policy for a generic CNI plugin.
    """
    def __init__(self, network_name):

        self._client = DatastoreClient()
        """
        DatastoreClient for access to the Calico datastore.
        """

        self.profile_name = network_name
        """
        Name of profile for attach to endpoint.
        """

        # Validate the given network name to make sure it is compatible with
        # Calico policy.
        if not validate_characters(network_name):
            raise ValueError("Invalid characters detected in the given network "
                             "name, %s. Only letters a-z, numbers 0-9, and "
                             "symbols _.- are supported.", network_name)

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

            # Apply any additonal tags.
            tags = self.generate_tags()
            if tags:
                _log.debug("Applying additional tags: %s", tags)
                profile = self._client.get_profile(self.profile_name)
                profile.tags.update(tags)
                self._client.profile_update_tags(profile)

        # Check if the profile has already been applied.
        if self.profile_name in endpoint.profile_ids:
            _log.warning("Endpoint already in profile %s", 
                         self.profile_name)
            return

        # Append profile to Calico endpoint.
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

    def generate_tags(self):
        """Generates Calico Tags for a profile.

        :rtype List
        :return: List of tags to apply to this profile.
        """
        return []


class DefaultDenyInboundDriver(DefaultPolicyDriver):
    """
    This driver rejects all incoming traffic, but allows all outgoing traffic.
    """
    def generate_rules(self):
        return Rules(id=self.profile_name,
                     inbound_rules=[Rule(action="deny")],
                     outbound_rules=[Rule(action="allow")])

    def remove_profile(self):
        _log.info("default-deny-inbound driver, do not remove profile")


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


class KubernetesAnnotationDriver(DefaultPolicyDriver):
    """
    Implements network policy for Kubernetes using annotations.
    """
    def __init__(self, pod_name, namespace, auth_token, api_root): 
        self.pod_name = pod_name
        self.namespace = namespace 
        self.policy_parser = calico_cni.policy_parser.PolicyParser(namespace)
        self.auth_token = auth_token 
        self.api_root = api_root 
        self.profile_name = "%s_%s" % (namespace, pod_name)
        self._annotation_key = "projectcalico.org/policy"
        self.ns_tag = self._escape_chars("namespace=%s" % self.namespace)
        self.pod = None

        # Call superclass.
        DefaultPolicyDriver.__init__(self, self.profile_name)

    def remove_profile(self):
        """Deletes the profile for this pod.
        """
        try:
            _log.info("Deleting Calico profile: %s", self.profile_name)
            self._client.remove_profile(self.profile_name)
        except KeyError:
            _log.warning("Profile %s does not exist, cannot delete", 
                    self.profile_name)

    def generate_rules(self):
        """Generates rules based on Kubernetes annotations. 
        """
        # Get the pod from the API.
        self.pod = self._get_api_pod()

        # Get any annotations.
        annotations = self._get_metadata("annotations")
        _log.debug("Found annotations: %s", annotations)

        # Outbound rules are always "allow".
        outbound_rules = [Rule(action="allow")]

        if self.namespace == "kube-system" :
            # Pods in the kube-system namespace must be accessible by all
            # other pods for services like DNS to work.
            _log.info("Pod is in kube-system namespace - allow all")
            inbound_rules = [Rule(action="allow")]
        elif annotations and self._annotation_key in annotations:
            # If policy annotations are defined, use them to generate rules.
            _log.info("Generating advanced policy from annotations")
            rules = annotations[self._annotation_key]
            inbound_rules = []
            for rule in rules.split(";"):
                try:
                    parsed_rule = self.policy_parser.parse_line(rule)
                except ValueError:
                    # Invalid rule specified.
                    _log.error("Invalid policy defined: %s", rule)
                    raise ApplyProfileError("Invalid policy defined", 
                                            details=rule) 
                else:
                    # Rule was valid - append.
                    inbound_rules.append(parsed_rule)
        else:
            # Isolate on namespace boundaries by default.
            _log.info("No policy annotations - apply namespace isolation")
            inbound_rules = [Rule(action="allow", src_tag=self.ns_tag)]
        
        return Rules(id=self.profile_name,
                     inbound_rules=inbound_rules,
                     outbound_rules=outbound_rules)

    def generate_tags(self):
        tags = set()

        # Grab namespace and create a tag if it exists.
        tags.add(self.ns_tag)

        # Create tags from labels
        labels = self._get_metadata("labels")
        _log.debug("Found labels: %s", labels)
        if labels:
            for k, v in labels.iteritems():
                tag = self.policy_parser.label_to_tag(k, v)
                _log.debug('Generated tag: %s', tag)
                tags.add(tag)
        return tags

    def _get_api_pod(self):
        """Get the pod resource from the API.

        :return: JSON object containing the pod spec
        """
        with requests.Session() as session:
            if self.auth_token:
                _log.debug('Updating header with Token %s', self.auth_token)
                session.headers.update({'Authorization':
                                        'Bearer ' + self.auth_token})

            # Generate the API endpoint to query.
            path = "namespaces/%s/pods/%s" % (self.namespace, self.pod_name)
            path = os.path.join(self.api_root, path)

            # Perform the API query and handle the result.
            try:
                _log.debug('Querying Kubernetes API for Pod: %s', path)
                response = session.get(path, verify=False)
            except BaseException, e:
                _log.exception("Exception hitting Kubernetes API")
                raise ApplyProfileError("Error querying Kubernetes API", 
                        details=str(e.message))
            else:
                # Check the HTTP response code for errors.
                if response.status_code != 200:
                    _log.error("Response from API returned %s Error:\n%s",
                                response.status_code,
                                response.text)
                    raise ApplyProfileError("Error querying Kubernetes API",
                                            details=str(response.text))

        # Success.
        _log.debug("Kubernetes API Response: %s", response.text)
        try:
            pod = json.loads(response.text)
        except TypeError:
            _log.exception("Error parsing Kubernetes API response")
            raise ApplyProfileError("Error parsing Kubernetes API response",
                    details=str(response.text))
        return pod

    def _get_metadata(self, key):
        """
        Returns the requested metadata, or None if it does not exist.
        """
        try:
            val = self.pod['metadata'][key]
        except (KeyError, TypeError):
            _log.debug('No %s found in pod %s', key, self.pod)
            return None
        return val

    def _escape_chars(self, unescaped_string):
        """
        Calico can only handle 3 special chars, '_.-'
        This function uses regex sub to replace SCs with '_'
        """
        # Character to replace symbols
        swap_char = '_'

        # If swap_char is in string, double it.
        unescaped_string = re.sub(swap_char, "%s%s" % (swap_char, swap_char),
                                  unescaped_string)

        # Substitute all invalid chars.
        return re.sub('[^a-zA-Z0-9\.\_\-]', swap_char, unescaped_string)


class ApplyProfileError(Exception):
    """
    Attempting to apply a profile to an endpoint that does not exist.
    """
    def __init__(self, msg=None, details=None):
        Exception.__init__(self, msg)
        self.details = details


def get_policy_driver(k8s_pod_name, k8s_namespace, net_config):
    """Returns a policy driver based on CNI configuration arguments.

    :return: a policy driver 
    """
    # Extract policy config and network name.
    policy_config = net_config.get(POLICY_KEY, {})
    network_name = net_config["name"]
    policy_type = policy_config.get("type")

    # Determine which policy driver to use.
    if policy_type == POLICY_MODE_DENY_INBOUND:
        # Use the deny-inbound driver. 
        driver_cls = DefaultDenyInboundDriver 
        driver_args = [network_name]
    elif k8s_pod_name:
        # Runing under Kubernetes - decide which Kubernetes driver to use.
        if policy_type == POLICY_MODE_ANNOTATIONS: 
            _log.debug("Using Kubernetes Annotation Policy Driver")
            assert k8s_namespace, "Missing Kubernetes namespace"
            k8s_auth_token = policy_config.get(AUTH_TOKEN_KEY)
            k8s_api_root = policy_config.get(API_ROOT_KEY, 
                                             "https://10.100.0.1:443/api/v1/")
            driver_cls = KubernetesAnnotationDriver
            driver_args = [k8s_pod_name, 
                           k8s_namespace, 
                           k8s_auth_token,
                           k8s_api_root]
        else:
            _log.debug("Using Default Kubernetes Policy Driver")
            driver_cls = KubernetesDefaultPolicyDriver
            driver_args = [network_name]
    else:
        _log.debug("Using default policy driver")
        driver_cls = DefaultPolicyDriver
        driver_args = [network_name]

    # Create an instance of the driver class.
    try:
        _log.debug("Creating instance of %s with args %s", 
                   driver_cls, driver_args)
        driver = driver_cls(*driver_args)
    except ValueError as e:
        # ValueError raised because profile name passed into
        # policy driver contains illegal characters.
        print_cni_error(ERR_CODE_GENERIC, e.message)
        sys.exit(ERR_CODE_GENERIC)

    return driver
