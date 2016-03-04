import logging
from constants import *
from pycalico.datastore import DatastoreClient
from pycalico.datastore_errors import MultipleEndpointsMatch

_log = logging.getLogger("__main__")
client = DatastoreClient()


def add_update_pod(key, pod):
    """
    Takes a new or updated pod from the Kubernetes API and
    creates the corresponding Calico configuration.
    """
    _log.info("Adding new pod: %s", key)

    # Get the Calico endpoint.  This may or may not have already been
    # created by the CNI plugin.  If it hasn't been created, we need to
    # wait until is has before we can do any meaningful work.
    namespace = pod["metadata"]["namespace"]
    name = pod["metadata"]["name"]
    workload_id = "%s.%s" % (namespace, name)
    try:
        _log.debug("Looking for endpoint that matches workload_id=%s",
                   workload_id)
        endpoint = client.get_endpoint(
            orchestrator_id="k8s",
            workload_id=workload_id
        )
    except KeyError:
        # We don't need to do anything special here, just return.
        # We'll receive another update when the Pod enters running state.
        _log.warn("No endpoint for '%s', wait until running", workload_id)
        return
    except MultipleEndpointsMatch:
        # We should never have multiple endpoints with the same
        # workload_id.  This could theoretically occur if the Calico
        # datastore is out-of-sync with what pods actually exist, but
        # this is an error state and indicates a problem elsewhere.
        _log.error("Multiple Endpoints found matching ID %s", workload_id)
        sys.exit(1)

    # Get Kubernetes labels.
    labels = pod["metadata"].get("labels", {})
    _log.debug("Pod '%s' has labels: %s", key, labels)

    # Add a special label for the Kubernetes namespace.  This is used
    # by selector-based policies to select all pods in a given namespace.
    labels[K8S_NAMESPACE_LABEL] = namespace

    # Set the labels on the endpoint.
    endpoint.labels = labels
    client.set_endpoint(endpoint)
    _log.info("Updated labels on pod %s", key)

    # Configure this pod with its namespace profile.
    ns_profile = NS_PROFILE_FMT % namespace
    client.set_profiles_on_endpoint([ns_profile],
                                    orchestrator_id="k8s",
                                    workload_id=endpoint.workload_id)


def delete_pod(key, pod):
    """
    We don't need to do anything when a pod is deleted - the CNI plugin
    handles the deletion of the endpoint.
    """
    _log.info("Pod deleted: %s", key)
