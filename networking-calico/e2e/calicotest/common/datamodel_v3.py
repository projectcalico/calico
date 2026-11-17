# -*- coding: utf-8 -*-
# Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
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

import json
import logging
import uuid

from etcd3gw.utils import _encode

from calicotest.common import etcdv3
from calicotest.common.timestamp import timestamp_now


# Particular JSON key strings.
DATASTORE_READY = "datastoreReady"

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


def put(
    resource_kind,
    name,
    spec,
    mod_revision=None,
    labels=None,
    corrupt=False,
    region=None,
):
    """Write a Calico v3 resource to etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name.  This is used to form its etcd key,
      and also goes in its .Metadata.Name field.

    - spec (dict): Resource spec, as a dict with keys as specified by the
      'json:' comments in the relevant golang struct definition (for example,
      WorkloadEndpointSpec in
      https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/apis/internalapi/workloadendpoint.go).

    - mod_revision (string): If specified, indicates that the write should only
      proceed if replacing an existing value with that mod_revision.

    Returns True if the write happened successfully; False if not.
    """
    client = etcdv3._get_client()
    key = _build_key(resource_kind, name, region=region)
    try:
        # Get the existing resource so we can persist its metadata.
        value = _get_inc_calico_metadata(resource_kind, name)
    except (etcdv3.KeyNotFound, ValueError):
        # Build basic resource structure.
        value = {
            "kind": resource_kind,
            "apiVersion": "projectcalico.org/v3",
            "metadata": {
                "name": name,
            },
        }
    if labels:
        value["metadata"]["labels"] = labels
    # Ensure namespace set, for a namespaced resource.
    if _is_namespaced(resource_kind):
        if region is None:
            value["metadata"]["namespace"] = "openstack"
        else:
            value["metadata"]["namespace"] = "openstack-region-%s" % region
    # Ensure that there is a creation timestamp.
    if "creationTimestamp" not in value["metadata"]:
        value["metadata"]["creationTimestamp"] = timestamp_now()
    # Ensure that there is a UID.
    if "uid" not in value["metadata"]:
        value["metadata"]["uid"] = str(uuid.uuid4())
    # Set the new spec (overriding whatever may already be there).
    value["spec"] = spec

    LOG.debug("etcdv3 put key=%s value=%s", key, value)
    value_as_string = json.dumps(value)
    if corrupt:
        value_as_string = value_as_string[:-1] + "X"
    if mod_revision:
        base64_key = _encode(key)
        base64_value = _encode(value_as_string)
        result = client.transaction(
            {
                "compare": [
                    {
                        "key": base64_key,
                        "result": "EQUAL",
                        "target": "MOD",
                        "mod_revision": mod_revision,
                    }
                ],
                "success": [
                    {
                        "request_put": {
                            "key": base64_key,
                            "value": base64_value,
                        },
                    }
                ],
                "failure": [],
            }
        )
        LOG.debug("transaction result %s", result)
        succeeded = result.get("succeeded", False)
    else:
        succeeded = client.put(key, value_as_string)
    return succeeded


def get(resource_kind, name, region=None):
    """Read spec of a Calico v3 resource from etcdv3.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name, which is used to form its etcd key.

    Returns the resource spec as a dict with keys as specified by the 'json:'
    comments in the relevant golang struct definition (for example,
    WorkloadEndpointSpec in
    https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/apis/internalapi/workloadendpoint.go).

    Raises etcdv3.KeyNotFound if there is no resource with that kind and name.
    """
    value = _get_inc_calico_metadata(resource_kind, name, region=region)
    return value["spec"]


def get_all(resource_kind, region=None):
    """Read all Calico v3 resources of a certain kind from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    Returns a list of tuples (name, spec, mod_revision), one for each resource
    of the specified kind, in which:

    - name is the resource's name (a string)

    - spec is a dict with keys as specified by the 'json:' comments in the
      relevant golang struct definition (for example, WorkloadEndpointSpec in
      https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/apis/internalapi/workloadendpoint.go).

    - mod_revision is the revision at which that resource was last modified (an
      integer represented as a string).
    """
    client = etcdv3._get_client()
    prefix = _build_key(resource_kind, "", region=region)
    results = client.get_prefix(prefix)
    LOG.debug("etcdv3 get_prefix %s results=%s", prefix, len(results))
    tuples = []
    for result in results:
        value, item = result
        value_dict = json.loads(value)
        LOG.debug("value dict: %s", value_dict)
        resource_tuple = (
            value_dict["metadata"]["name"],
            value_dict["spec"],
            item["mod_revision"],
        )
        tuples.append(resource_tuple)
    return tuples


def delete(resource_kind, name, region=None):
    """Delete a Calico v3 resource from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name, which is used to form its etcd key.

    Returns True if the deletion was successful; False if not.
    """
    client = etcdv3._get_client()
    key = _build_key(resource_kind, name, region=region)
    LOG.debug("etcdv3 delete key=%s", key)
    deleted = client.delete(key)
    LOG.debug("etcdv3 deleted=%s", deleted)
    return deleted


def get_prefix(prefix):
    """Read all etcdv3 data whose key begins with a given prefix.

    - prefix (string): The prefix.

    Returns a list of tuples (key, value), one for each key-value pair, in
    which:

    - key is the etcd key (a string)

    - value is the etcd value (also a string; note *not* JSON-decoded).

    Note: this entrypoint is only used for data outside the Calico v3 data
    model; specifically for legacy Calico v1 status notifications.  This
    entrypoint should be removed once those status notifications have been
    reimplemented within the Calico v3 data model.
    """
    client = etcdv3._get_client()
    results = client.get_prefix(prefix)
    LOG.debug("etcdv3 get_prefix %s results=%s", prefix, len(results))
    tuples = []
    for result in results:
        value, item = result
        result_tuple = (item["key"], value)
        tuples.append(result_tuple)
    return tuples


def get_current_revision():
    """Get the current etcdv3 revision."""
    client = etcdv3._get_client()
    status = client.status()
    LOG.debug("etcdv3 status %s", status)
    return status["header"]["revision"]


def _is_namespaced(resource_kind):
    if resource_kind == "WorkloadEndpoint":
        return True
    if resource_kind == "NetworkPolicy":
        return True
    return False


def _plural(resource_kind):
    if resource_kind == "NetworkPolicy":
        return "NetworkPolicies"
    if resource_kind == "GlobalNetworkPolicy":
        return "GlobalNetworkPolicies"
    return resource_kind + "s"


def _build_key(resource_kind, name, region=None):
    if _is_namespaced(resource_kind):
        if region is not None:
            namespace = "openstack-region-%s" % region
        else:
            namespace = "openstack"
        template = "/calico/resources/v3/projectcalico.org/%s/" + namespace + "/%s"
    else:
        template = "/calico/resources/v3/projectcalico.org/%s/%s"
    return template % (_plural(resource_kind).lower(), name)


def _get_inc_calico_metadata(resource_kind, name, region=None):
    client = etcdv3._get_client()
    key = _build_key(resource_kind, name, region=region)
    results = client.get(key, metadata=False)
    LOG.debug("etcdv3 get key=%s results=%s", key, results)
    if len(results) != 1:
        raise etcdv3.KeyNotFound()
    value = json.loads(results[0])
    return value
