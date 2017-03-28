# Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
from pycalico.datastore import DatastoreClient

_log = logging.getLogger("__main__")
client = DatastoreClient()

label_cache = {}
endpoint_cache = {}


def parse_pod(pod):
    """
    Return the labels for this pod.
    """
    # Get Kubernetes labels.
    labels = pod["metadata"].get("labels", {})

    # Extract information.
    namespace = pod["metadata"]["namespace"]
    name = pod["metadata"]["name"]
    workload_id = "%s.%s" % (namespace, name)

    # Add a special label for the Kubernetes namespace.  This is used
    # by selector-based policies to select all pods in a given namespace.
    labels[K8S_NAMESPACE_LABEL] = namespace

    return workload_id, namespace, name, labels


def add_pod(pod):
    """
    Called when a Pod update with type ADDED is received.

    Simply store the pod's labels in the label cache so that we
    can accurately determine if an endpoint must be updated on subsequent
    updates.  The Calico CNI plugin has already configured this pod's
    endpoint with the correct labels, so we don't need to modify the
    endpoint object.
    """
    workload_id, _, _, labels = parse_pod(pod)
    label_cache[workload_id] = labels
    _log.debug("Updated label cache with %s: %s", workload_id, labels)


def update_pod(pod):
    """
    Called when a Pod update with type MODIFIED is received.

    Compares if the labels have changed.  If they have, updates
    the Calico endpoint for this pod.
    """
    # Get Kubernetes labels and metadata.
    workload_id, namespace, name, labels = parse_pod(pod)
    _log.debug("Updating pod: %s", workload_id)

    # Check if the labels have changed for this pod.  If they haven't,
    # do nothing.
    old_labels = label_cache.get(workload_id)
    _log.debug("Compare labels on %s. cached: %s, new: %s",
               workload_id, old_labels, labels)
    if old_labels == labels:
        _log.debug("Ignoring updated for %s with no label change", workload_id)
        return

    # Labels have changed.
    # Check our cache to see if we already know about this endpoint.  If not,
    # re-load the entire cache from etcd and try again.
    _log.info("Labels for %s have been updated", workload_id)
    endpoint = endpoint_cache.get(workload_id)
    if not endpoint:
        # No endpoint in our cache.
        _log.info("No endpoint for %s in cache, loading", workload_id)
        load_caches()
        endpoint = endpoint_cache.get(workload_id)
        if not endpoint:
            # No endpoint in etcd - this means the pod hasn't been
            # created by the CNI plugin yet.  Just wait until it has been.
            # This can only be hit when labels for a pod change before
            # the pod has been deployed, so should be pretty uncommon.
            _log.info("No endpoint for pod %s - wait for creation",
                      workload_id)
            return
    _log.debug("Found endpoint for %s", workload_id)

    # Update the labels on the endpoint.
    endpoint.labels = labels
    client.set_endpoint(endpoint)

    # Update the label cache with the new labels.
    label_cache[workload_id] = labels

    # Update the endpoint cache with the modified endpoint.
    endpoint_cache[workload_id] = endpoint


def load_caches():
    """
    Loads endpoint and label caches from etcd.

    We need to do this when we've received a MODIFIED event
    indicating that labels have changed for a pod that is not
    already in our cache. This can also happen if there are no labels
    cached for the MODIFIED pod.
    """
    endpoints = client.get_endpoints(orchestrator_id="k8s")
    for ep in endpoints:
        endpoint_cache[ep.workload_id] = ep
        label_cache[ep.workload_id] = ep.labels
    _log.info("Loaded endpoint and label caches")


def delete_pod(pod):
    """
    We don't need to do anything when a pod is deleted - the CNI plugin
    handles the deletion of the endpoint.  Just update the caches.
    """
    # Extract information.
    workload_id, _, _, _ = parse_pod(pod)
    _log.debug("Pod deleted: %s", workload_id)

    # Delete from label cache.
    try:
        del label_cache[workload_id]
        _log.debug("Removed %s from label cache", workload_id)
    except KeyError:
        pass

    # Delete from endpoint cache.
    try:
        del endpoint_cache[workload_id]
        _log.debug("Removed %s from endpoint cache", workload_id)
    except KeyError:
        pass
