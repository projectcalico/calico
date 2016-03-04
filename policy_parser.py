#!/usr/bin/python
import sys
import logging

from pycalico.datastore_datatypes import Rules, Rule
from cloghandler import ConcurrentRotatingFileHandler

from constants import *

_log = logging.getLogger("__main__")


class PolicyError(Exception):
    def __init__(self, msg=None, policy=None):
        Exception.__init__(self, msg)
        self.policy = policy


class PolicyParser(object):
    def __init__(self, policy):
        self.namespace = policy["metadata"]["namespace"]
        self.policy = policy

    def calculate_inbound_rules(self):
        """
        Takes a NetworkPolicy object from the API and returns a list of
        Calico Rules objects which should be applied on ingress.
        """
        _log.debug("Calculating inbound rules")
        rules = []

        # Iterate through and create the appropriate Calico Rules.
        allow_incomings = self.policy["spec"].get("ingress") or []
        _log.info("Found %s ingress rules", len(allow_incomings))
        for allow_incoming_clause in allow_incomings:
            # Convert each allow_incoming_clause into one or more
            # Calico Rule objects.
            if allow_incoming_clause:
                # Rule exists - parse it.
                r = self._allow_incoming_to_rules(allow_incoming_clause)
            else:
                # An empty rule means allow all traffic.
                r = [Rule(action="allow")]
            rules.extend(r)

        _log.debug("Calculated total set of rules: %s", rules)
        return rules

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
            pods_present = "pods" in from_clause
            namespaces_present = "namespaces" in from_clause
            _log.debug("Is 'pods:' present? %s", pods_present)
            _log.debug("Is 'namespaces:' present? %s", namespaces_present)

            if pods_present and namespaces_present:
                # This is an error case according to the API.
                msg = "Policy API does not support both 'pods' and " \
                      "'namespaces' selectors."
                raise PolicyError(msg, self.policy)
            elif pods_present:
                # There is a pod selector in this "from" clause.
                pod_selector = from_clause["pods"] or {}
                _log.debug("Allow from pods: %s", pod_selector)
                selectors = ["%s == '%s'" % (k, v) for k, v
                             in pod_selector.iteritems()]

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
                namespaces = from_clause["namespaces"] or {}
                _log.debug("Allow from namespaces: %s", namespaces)
                selectors = ["%s == '%s'" % (NS_LABEL_KEY_FMT % k, v)
                             for k, v in namespaces.iteritems()]
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
            protocol = to_port.get("protocol")
            port = to_port.get("port")
            ports = ports_by_protocol.setdefault(protocol, [])
            if port:
                _log.debug("Allow to port: %s/%s", protocol, port)
                ports.append(port)

        # For each protocol, create a "to_arg" which allows to
        # the ports specified for that protocol.
        to_args = []
        for protocol, ports in ports_by_protocol.iteritems():
            arg = {"protocol": protocol.lower()}
            if ports:
                arg["dst_ports"] = ports
            to_args.append(arg)
        return to_args
