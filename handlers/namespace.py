import logging
from constants import *
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rules, Rule

_log = logging.getLogger("__main__")
client = DatastoreClient()


def add_update_namespace(key, namespace):
    """
    Configures the necessary policy in Calico for this
    namespace.  Uses the `net.alpha.kubernetes.io/network-isolation`
    annotation.
    """
    _log.info("Adding/updating namespace: %s", key)

    # Determine the type of network-isolation specified by this namespace.
    # This defaults to no isolation.
    annotations = namespace["metadata"].get("annotations", {})
    _log.debug("Namespace %s has annotations: %s", key, annotations)
    net_isolation = annotations.get(NS_POLICY_ANNOTATION, "no") == "yes"
    _log.info("Namespace %s has network-isolation? %s", key, net_isolation)

    # Determine the profile name to create.
    namespace_name = namespace["metadata"]["name"]
    profile_name = NS_PROFILE_FMT % namespace_name

    # Determine the rules to use.
    outbound_rules = [Rule(action="allow")]
    if net_isolation:
        inbound_rules = [Rule(action="deny")]
    else:
        inbound_rules = [Rule(action="allow")]
    rules = Rules(id=profile_name,
                  inbound_rules=inbound_rules,
                  outbound_rules=outbound_rules)

    # Assign labels to the profile.  We modify the keys to use
    # a special prefix to indicate that these labels are inherited
    # from the namespace.
    ns_labels = namespace["metadata"].get("labels", {})
    labels = {NS_LABEL_KEY_FMT % k: v for k, v in ns_labels.iteritems()}
    _log.debug("Generated namespace labels: %s", labels)

    # Create the Calico profile to represent this namespace, or
    # update it if it already exists.
    client.create_profile(profile_name, rules, labels)

    _log.info("Created/updated profile for namespace %s", namespace_name)


def delete_namespace(key, namespace):
    """
    Takes a deleted namespace and removes the corresponding
    configuration from the Calico datastore.
    """
    _log.info("Deleting namespace: %s", key)

    # Delete the Calico policy which represnets this namespace.
    namespace_name = namespace["metadata"]["name"]
    profile_name = NS_PROFILE_FMT % namespace_name
    try:
        client.remove_profile(profile_name)
    except KeyError:
        _log.info("Unable to find profile for namespace '%s'", key)
