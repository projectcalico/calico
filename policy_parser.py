# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

import logging

from constants import *
from pycalico.datastore_datatypes import Rule

_log = logging.getLogger("__main__")


class PolicyError(Exception):
    def __init__(self, msg=None, policy=None):
        Exception.__init__(self, msg)
        self.policy = policy


class PolicyParser(object):
    """
    Parser for Kubernetes NetworkPolicy API objects.

    They are defined by the NetworkPolicySpec in the /apis/networking API
    group.
    """
    def __init__(self, policy):
        """
        Create a Parser for a Kubernetes NetworkPolicy API object.

        Returns the parser.
        """
        self.policy = policy
        self.namespace = self.policy["metadata"]["namespace"]

    def calculate_pod_selector(self):
        """
        Generate the Calico representation of the policy.spec.podSelector for
        this Policy.

        Returns the endpoint selector in the Calico datamodel format.
        """
        _log.debug("Calculating pod selector")

        # PodSelectors only select pods from the Policy's namespace.
        calico_selectors = ["%s == '%s'" % (K8S_NAMESPACE_LABEL, self.namespace)]

        calico_selectors += \
            self._calculate_selectors(self.policy["spec"]["podSelector"])

        _log.debug("Selector with %d filters" % len(calico_selectors))
        return " && ".join(calico_selectors)

    def calculate_inbound_rules(self):
        """
        Generate Calico Rule objects for this Policy's ingress rules.

        Returns a list of Calico datamodel Rules.
        """
        _log.debug("Calculating inbound rules")
        rules = []

        ingress_rules = self.policy["spec"].get("ingress")
        if ingress_rules:
            _log.debug("Got %d ingress rules: translating to Calico format",
                       len(ingress_rules))
            for ingress_rule in ingress_rules:
                _log.debug("Processing ingress rule %s", ingress_rule)
                if ingress_rule:
                    # Convert ingress rule into Calico Rules.
                    _log.debug("Adding rule %s", ingress_rule)
                    rules.extend(self._allow_incoming_to_rules(ingress_rule))
                else:
                    # An empty rule means allow all traffic.
                    _log.debug("Empty rule => allow all; skipping rest")
                    rules.append(Rule(action="allow"))
                    break

        _log.debug("Calculated total set of rules: %s", rules)
        return rules

    def _calculate_selectors(self, label_selector, key_format="%s"):
        """
        Generate Calico datamodel selectors for a Kubernetes LabelSelector.

        Returns a list of selectors in the Calico datamodel format.
        """
        # A null LabelSelector matches no objects.
        calico_selectors = []

        # matchLabels is a map key => value, it means match if (label[key] ==
        # value) for all keys.
        if "matchLabels" in label_selector:
            labels = label_selector["matchLabels"]
            calico_selectors += [
                "%s == '%s'" % (key_format % k, v) for k, v in labels.iteritems()
            ]

        # matchExpressions is a list of in/notin/exists/doesnotexist tests.
        if "matchExpressions" in label_selector:
            for expression in label_selector["matchExpressions"]:
                key = key_format % expression["key"]
                operator = expression["operator"]
                values = expression.get("values", [])
                value_list = ", ".join(["\"%s\"" % v for v in values])
                if operator == "In":
                    calico_selectors.append("%s in { %s }" % (key, value_list))
                elif operator == "NotIn":
                    calico_selectors.append("%s not in { %s }" % (key, value_list))
                elif operator == "Exists":
                    calico_selectors.append("has(%s)" % key)
                elif operator == "DoesNotExist":
                    calico_selectors.append("! has(%s)" % key)
                else:
                    raise PolicyError("Unknown operator: %s" % operator)

        return calico_selectors

    def _allow_incoming_to_rules(self, allow_incoming_clause):
        """
        Takes a single "allowIncoming" rule from a NetworkPolicy object
        and returns a list of Calico Rule object with implement it.
        """
        _log.debug("Processing ingress rule: %s", allow_incoming_clause)

        # Generate to "to" arguments for this Rule.
        ports = allow_incoming_clause.get("ports")
        if ports:
            _log.debug("Parsing 'ports': %s", ports)
            to_args = self._generate_to_args(ports)
        else:
            _log.debug("No ports specified, allow all protocols / ports")
            to_args = [{}]

        # Generate "from" arguments for this Rule.
        froms = allow_incoming_clause.get("from")
        if froms:
            _log.debug("Parsing 'from': %s", froms)
            from_args = self._generate_from_args(froms)
        else:
            _log.debug("No from specified, allow from all sources")
            from_args = [{}]

        # Create a Rule per-protocol, per-from-clause.
        _log.debug("Creating rules")
        rules = []
        for to_arg in to_args:
            for from_arg in from_args:
                _log.debug("\tAllow from %s to %s", from_arg, to_arg)
                args = {"action": "allow"}
                args.update(from_arg)
                args.update(to_arg)
                rules.append(Rule(**args))
        return rules

    def _generate_from_args(self, froms):
        """
        Generate an arguments dictionary suitable for passing to
        the constructor of a libcalico Rule object using the given
        "from" clauses.
        """
        from_args = []
        for from_clause in froms:
            # We need to check if the key exists, not just if there is
            # a non-null value.  The presence of the key with a null
            # value means "select all".
            _log.debug("Parsing 'from' clause: %s", from_clause)
            pods_present = "podSelector" in from_clause
            namespaces_present = "namespaceSelector" in from_clause
            _log.debug("Is 'podSelector:' present? %s", pods_present)
            _log.debug("Is 'namespaceSelector:' present? %s", namespaces_present)

            if pods_present and namespaces_present:
                # This is an error case according to the API.
                msg = "Policy API does not support both 'pods' and " \
                      "'namespaces' selectors."
                raise PolicyError(msg, self.policy)
            elif pods_present:
                # There is a pod selector in this "from" clause.
                pod_selector = from_clause["podSelector"] or {}
                _log.debug("Allow from podSelector: %s", pod_selector)
                selectors = self._calculate_selectors(pod_selector)

                # We can only select on pods in this namespace.
                selectors.append("%s == '%s'" % (K8S_NAMESPACE_LABEL,
                                                 self.namespace))
                selector = " && ".join(selectors)

                # Append the selector to the from args.
                _log.debug("Allowing pods which match: %s", selector)
                from_args.append({"src_selector": selector})
            elif namespaces_present:
                # There is a namespace selector.  Namespace labels are
                # applied to each pod in the namespace using
                # the per-namespace profile.  We can select on namespace
                # labels using the NS_LABEL_KEY_FMT modifier.
                namespaces = from_clause["namespaceSelector"] or {}
                _log.debug("Allow from namespaceSelector: %s", namespaces)
                selectors = self._calculate_selectors(namespaces,
                                                      NS_LABEL_KEY_FMT)
                selector = " && ".join(selectors)
                if selector:
                    # Allow from the selected namespaces.
                    _log.debug("Allowing from namespaces which match: %s",
                               selector)
                    from_args.append({"src_selector": selector})
                else:
                    # Allow from all pods in all namespaces.
                    _log.debug("Allowing from all pods in all namespaces")
                    selector = "has(%s)" % K8S_NAMESPACE_LABEL
                    from_args.append({"src_selector": selector})
        return from_args

    def _generate_to_args(self, ports):
        """
        Generates an arguments dictionary suitable for passing to
        the constructor of a libcalico Rule object from the given ports.
        """
        # Generate a list of ports allow for each specified
        # protocol.
        ports_by_protocol = {}
        for to_port in ports:
            # Keep a dict of ports exposed, keyed by protocol.
            protocol = to_port.get("protocol", "tcp").lower()
            port = to_port.get("port")
            ports = ports_by_protocol.setdefault(protocol, [])
            if port:
                _log.debug("Allow to port: %s/%s", protocol, port)
                ports.append(port)

        # For each protocol, create a "to_arg" which allows to
        # the ports specified for that protocol.
        to_args = []
        for protocol, ports in ports_by_protocol.iteritems():
            arg = {"protocol": protocol}
            if ports:
                arg["dst_ports"] = ports
            to_args.append(arg)
        return to_args
