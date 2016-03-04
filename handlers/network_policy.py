import logging
import json

from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rules, Rule

from constants import *
from policy_parser import PolicyParser, PolicyError

_log = logging.getLogger("__main__")
client = DatastoreClient()


def add_update_network_policy(key, policy):
    """
    Takes a new network policy from the Kubernetes API and
    creates the corresponding Calico policy configuration.
    """
    _log.info("Adding new network policy: %s", key)

    # Parse this network policy so we can convert it to the appropriate
    # Calico policy.  First, get the selector from the API object.
    k8s_selector = policy["spec"]["podSelector"]
    k8s_selector = k8s_selector or {}

    # Build the appropriate Calico label selector.  This is done using
    # the labels provided in the NetworkPolicy, as well as the
    # NetworkPolicy's namespace.
    namespace = policy["metadata"]["namespace"]
    selectors = ["%s == '%s'" % (k, v) for k, v in
                 k8s_selector.iteritems()]
    selectors += ["%s == '%s'" % (K8S_NAMESPACE_LABEL, namespace)]
    selector = " && ".join(selectors)

    # Determine the name for this policy.
    name = "%s.%s" % (policy["metadata"]["namespace"],
                      policy["metadata"]["name"])

    # Build the Calico rules.
    try:
        inbound_rules = PolicyParser(policy).calculate_inbound_rules()
    except Exception:
        # It is possible bad rules will be passed - we don't want to
        # crash the agent, but we do want to indicate a problem in the
        # logs, so that the policy can be fixed.
        _log.exception("Error parsing policy: %s",
                       json.dumps(policy, indent=2))
    else:
        rules = Rules(id=name,
                      inbound_rules=inbound_rules,
                      outbound_rules=[Rule(action="allow")])

        # Create the network policy using the calculated selector and rules.
        client.create_policy(NET_POL_TIER_NAME, name,
                             selector, order=10, rules=rules)
        _log.info("Updated policy '%s' for NetworkPolicy %s", name, key)


def delete_network_policy(key, policy):
    """
    Takes a deleted network policy and removes the corresponding
    configuration from the Calico datastore.
    """
    _log.info("Deleting network policy: %s", key)

    # Determine the name for this policy.
    name = "%s.%s" % (policy["metadata"]["namespace"],
                      policy["metadata"]["name"])

    # Delete the corresponding Calico policy
    try:
        client.remove_policy(NET_POL_TIER_NAME, name)
    except KeyError:
        _log.info("Unable to find policy '%s' - already deleted", key)
