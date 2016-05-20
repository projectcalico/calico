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

from pykube.config import KubeConfig
from pykube.http import HTTPClient
from pykube.objects import Pod
from pykube.query import Query

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


class KubernetesNoPolicyDriver(DefaultPolicyDriver):
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

    def __init__(self, pod_name, namespace, auth_token, api_root,
                 client_certificate, client_key, certificate_authority, kubeconfig):
        self.pod_name = pod_name
        self.namespace = namespace
        self.policy_parser = calico_cni.policy_parser.PolicyParser(namespace)
        self.auth_token = auth_token
        self.client_certificate = client_certificate
        self.client_key = client_key
        self.certificate_authority = certificate_authority or False
        self.kubeconfig_path = kubeconfig
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
        if self.namespace != "kube-system":
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
        # If kubeconfig was specified, use the pykube library.
        if self.kubeconfig_path:
            _log.info("Using kubeconfig at %s", self.kubeconfig_path)
            try:
                api = HTTPClient(KubeConfig.from_file(self.kubeconfig_path))
                pod = Query(api, Pod, self.namespace).get_by_name(self.pod_name)
                _log.info("Found pod: %s: ", pod.obj)
            except Exception as e:
                raise PolicyException("Error querying Kubernetes API",
                                      details=str(e.message))
            else:
                return pod.obj

        # Otherwise, use direct HTTP query to get pod.
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

                if self.client_certificate and self.client_key:
                    _log.debug("Using client certificate for Query API. "
                               "cert: %s, key: %s",
                               self.client_certificate,
                               self.client_key)
                    cert = (self.client_certificate,
                            self.client_key)
                    response = session.get(path, cert=cert,
                                           verify=self.certificate_authority)
                else:
                    _log.debug('Using direct connection for query API')
                    response = session.get(path,
                                           verify=self.certificate_authority)
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


class KubernetesPolicyDriver(KubernetesAnnotationDriver):
    """
    This driver sets the labels and correct profiles on the endpoint.

    The labels are fetched from the k8s API, and a special additional label is
    added.

    The profile ID is constructed from the namespace.
    """
    def apply_profile(self, endpoint):
        # Set profile
        profile_id = "k8s_ns.%s" % self.namespace
        _log.debug("Constructed profile ID - %s" % profile_id)
        endpoint.profile_ids = [profile_id]

        # Fetch and set the labels
        pod = self._get_api_pod()
        labels = pod["metadata"].get("labels", {})
        labels["calico/k8s_ns"] = self.namespace
        _log.debug("Got labels - %s" % labels)
        endpoint.labels = labels

        # Finally, update the endpoint.
        self._client.update_endpoint(endpoint)

    def remove_profile(self):
        # This policy driver didn't create any profiles so there are none to
        # delete.
        _log.debug("No profile to remove for pod %s", self.pod_name)


class PolicyException(Exception):
    """
    Generic base class for policy errors.
    """
    def __init__(self, msg=None, details=None):
        Exception.__init__(self, msg)
        self.details = details

class ApplyProfileError(PolicyException):
    """
    Attempting to apply a profile to an endpoint that does not exist.
    """
    pass


def get_policy_driver(cni_plugin):
    """Returns a policy driver based on CNI configuration arguments.

    :return: a policy driver
    """
    # Extract policy config and network name.
    policy_config = cni_plugin.network_config.get(POLICY_KEY, {})
    network_name = cni_plugin.network_config["name"]
    policy_type = policy_config.get("type")
    supported_policy_types = [None,
                              POLICY_MODE_KUBERNETES,
                              POLICY_MODE_KUBERNETES_ANNOTATIONS]
    if policy_type not in supported_policy_types:
        print_cni_error(ERR_CODE_GENERIC,
                        "policy type set to unsupported value (%s). "
                        "Supported values = %s" %
                        (policy_type, [x for x in supported_policy_types if x]))
        sys.exit(ERR_CODE_GENERIC)

    # Determine which policy driver to use.
    if cni_plugin.running_under_k8s:
        # Running under Kubernetes - decide which Kubernetes driver to use.
        if policy_type == POLICY_MODE_KUBERNETES_ANNOTATIONS or \
           policy_type == POLICY_MODE_KUBERNETES:
            assert cni_plugin.k8s_namespace, "Missing Kubernetes namespace"
            auth_token = policy_config.get(AUTH_TOKEN_KEY)
            api_root = policy_config.get(API_ROOT_KEY,
                                         "https://10.100.0.1:443/api/v1/")
            client_certificate = policy_config.get(K8S_CLIENT_CERTIFICATE_VAR)
            client_key = policy_config.get(K8S_CLIENT_KEY_VAR)
            certificate_authority = policy_config.get(
                K8S_CERTIFICATE_AUTHORITY_VAR)
            kubeconfig_path = policy_config.get("kubeconfig")

            if (client_key and not os.path.isfile(client_key)) or \
               (client_certificate and not os.path.isfile(client_certificate)) or \
               (certificate_authority and not os.path.isfile(certificate_authority)):
                print_cni_error(ERR_CODE_GENERIC,
                                "certificates provided but files don't exist")
                sys.exit(ERR_CODE_GENERIC)

            if policy_type == POLICY_MODE_KUBERNETES:
                _log.debug("Using Kubernetes Policy Driver")
                driver_cls = KubernetesPolicyDriver
            elif policy_type == POLICY_MODE_KUBERNETES_ANNOTATIONS:
                _log.debug("Using Kubernetes Annotation Policy Driver")
                driver_cls = KubernetesAnnotationDriver

            driver_args = [cni_plugin.k8s_pod_name,
                           cni_plugin.k8s_namespace,
                           auth_token,
                           api_root,
                           client_certificate,
                           client_key,
                           certificate_authority,
                           kubeconfig_path]
        else:
            _log.debug("Using Kubernetes Driver - no policy")
            driver_cls = KubernetesNoPolicyDriver
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
