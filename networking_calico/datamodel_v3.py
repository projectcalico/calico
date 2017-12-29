# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

import etcd
from etcd3gw.client import Etcd3Client
from etcd3gw.utils import _encode
import json
import uuid

from networking_calico.compat import cfg
from networking_calico.compat import log
from networking_calico.timestamp import timestamp_now


# Particular JSON key strings.
CLUSTER_GUID = 'clusterGUID'
CLUSTER_TYPE = 'clusterType'
DATASTORE_READY = 'datastoreReady'
ENDPOINT_REPORTING_ENABLED = 'endpointReportingEnabled'
INTERFACE_PREFIX = 'interfacePrefix'


LOG = log.getLogger(__name__)


def put(resource_kind, name, spec, mod_revision=None):
    """Write a Calico v3 resource to etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name.  This is used to form its etcd key,
      and also goes in its .Metadata.Name field.

    - spec (dict): Resource spec, as a dict with keys as specified by the
      'json:' comments in the relevant golang struct definition (for example,
      https://github.com/projectcalico/libcalico-go/blob/master/
      lib/apis/v3/workloadendpoint.go#L38).

    - mod_revision (string): If specified, indicates that the write should only
      proceed if replacing an existing value with that mod_revision.

    Returns True if the write happened successfully; False if not.
    """
    client = _get_client()
    key = _build_key(resource_kind, name)
    value = None
    try:
        # Get the existing resource so we can persist its metadata.
        value, _ = _get_with_metadata(resource_kind, name)
    except etcd.EtcdKeyNotFound:
        pass
    except ValueError:
        LOG.warning("etcd value not valid JSON, so ignoring")
    if value is None:
        # Build basic resource structure.
        value = {
            'kind': resource_kind,
            'apiVersion': 'projectcalico.org/v3',
            'metadata': {
                'name': name,
            },
        }
    # Ensure namespace set, for a namespaced resource.
    if _is_namespaced(resource_kind):
        value['metadata']['namespace'] = 'openstack'
    # Ensure that there is a creation timestamp.
    if 'creationTimestamp' not in value['metadata']:
        value['metadata']['creationTimestamp'] = timestamp_now()
    # Ensure that there is a UID.
    if 'uid' not in value['metadata']:
        value['metadata']['uid'] = uuid.uuid4().get_hex()
    # Set the new spec (overriding whatever may already be there).
    value['spec'] = spec

    LOG.debug("etcdv3 put key=%s value=%s", key, value)
    value_as_string = json.dumps(value)
    if mod_revision:
        base64_key = _encode(key)
        base64_value = _encode(value_as_string)
        result = client.transaction({
            'compare': [{
                'key': base64_key,
                'result': 'EQUAL',
                'target': 'MOD',
                'mod_revision': mod_revision,
            }],
            'success': [{
                'request_put': {
                    'key': base64_key,
                    'value': base64_value,
                },
            }],
            'failure': [],
        })
        LOG.debug("transaction result %s", result)
        succeeded = result.get('succeeded', False)
    else:
        succeeded = client.put(key, value_as_string)
    return succeeded


def get(resource_kind, name):
    """Read spec of a Calico v3 resource from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name, which is used to form its etcd key.

    Returns the resource spec as a dict with keys as specified by the 'json:'
    comments in the relevant golang struct definition (for example,
    https://github.com/projectcalico/libcalico-go/blob/master/
    lib/apis/v3/workloadendpoint.go#L38).

    Raises EtcdKeyNotFound if there is no resource with that kind and name.
    """
    spec, _ = get_with_mod_revision(resource_kind, name)
    return spec


def get_with_mod_revision(resource_kind, name):
    """Read spec of a Calico v3 resource from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name, which is used to form its etcd key.

    Returns (spec, mod_revision) where

    - spec is the resource spec as a dict with keys as specified by the 'json:'
      comments in the relevant golang struct definition (for example,
      https://github.com/projectcalico/libcalico-go/blob/master/
      lib/apis/v3/workloadendpoint.go#L38).

    - mod_revision is the etcdv3 revision at which the resource was last
      modified.

    Raises EtcdKeyNotFound if there is no resource with that kind and name.

    """
    value, item = _get_with_metadata(resource_kind, name)
    return value['spec'], item['mod_revision']


def get_all(resource_kind):
    """Read all Calico v3 resources of a certain kind from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    Returns a list of tuples (name, spec, mod_revision), one for each resource
    of the specified kind, in which:

    - name is the resource's name (a string)

    - spec is a dict with keys as specified by the 'json:' comments in the
      relevant golang struct definition (for example,
      https://github.com/projectcalico/libcalico-go/blob/master/
      lib/apis/v3/workloadendpoint.go#L38).

    - mod_revision is the revision at which that resource was last modified (an
      integer represented as a string).
    """
    client = _get_client()
    prefix = _build_key(resource_kind, '')
    results = client.get_prefix(prefix)
    LOG.debug("etcdv3 get_prefix %s results=%s", prefix, len(results))
    tuples = []
    for result in results:
        value, item = result
        try:
            value_dict = json.loads(value)
            LOG.debug("value dict: %s", value_dict)
            tuple = (
                value_dict['metadata']['name'],
                value_dict['spec'],
                item['mod_revision']
            )
            tuples.append(tuple)
        except ValueError:
            LOG.warning("etcd value not valid JSON, so ignoring (%s)", value)
    return tuples


def delete(resource_kind, name):
    """Delete a Calico v3 resource from etcd.

    - resource_kind (string): E.g. WorkloadEndpoint, Profile, etc.

    - name (string): The resource's name, which is used to form its etcd key.

    Returns True if the deletion was successful; False if not.
    """
    client = _get_client()
    key = _build_key(resource_kind, name)
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
    client = _get_client()
    results = client.get_prefix(prefix)
    LOG.debug("etcdv3 get_prefix %s results=%s", prefix, len(results))
    tuples = []
    for result in results:
        value, item = result
        tuple = (item['key'], value)
        tuples.append(tuple)
    return tuples


def watch_subtree(prefix, start_revision):
    """Watch for changes to etcdv3 data whose key begins with a given prefix.

    - prefix (string): The prefix.

    - start_revision (string representation of an integer): The revision to
      start watching from.  Events will be reported beginning from, and
      including, this revision.

    Returns a tuple (event_stream, cancel), in which:

    - event_stream is a generator that returns the next reported event, or None
      if cancel has been called.  Each event is a dict like

      {'kv': {'key': <string>,
              'value': <string>,
              'mod_revision': <string>,
              'create_revision': <string>,
              'version': <string>}}

      or

      {'type': 'DELETE',
       'kv': {'key': <key>,
              'mod_revision': <string>}}

    - cancel is a thunk that can be called to cancel the watch and cause the
      event_stream to return None.

    Note: this entrypoint is only used for data outside the Calico v3 data
    model; specifically for legacy Calico v1 status notifications.  This
    entrypoint should be updated or removed when those status notifications
    have been reimplemented within the Calico v3 data model.
    """
    LOG.info("Watch subtree %s", prefix)
    client = _get_client()
    event_stream, cancel = client.watch_prefix(prefix,
                                               start_revision=start_revision)
    return event_stream, cancel


def get_current_revision():
    """Get the current etcdv3 revision."""
    client = _get_client()
    status = client.status()
    LOG.debug("etcdv3 status %s", status)
    return status['header']['revision']


# Internals.
_client = None


def _get_client():
    global _client
    if not _client:
        calico_cfg = cfg.CONF.calico
        tls_config_params = [
            calico_cfg.etcd_key_file,
            calico_cfg.etcd_cert_file,
            calico_cfg.etcd_ca_cert_file,
        ]
        if any(tls_config_params):
            LOG.info("TLS to etcd is enabled with key file %s; "
                     "cert file %s; CA cert file %s", *tls_config_params)
            _client = Etcd3Client(host=calico_cfg.etcd_host,
                                  port=calico_cfg.etcd_port,
                                  protocol="https",
                                  ca_cert=calico_cfg.etcd_ca_cert_file,
                                  cert_key=calico_cfg.etcd_key_file,
                                  cert_cert=calico_cfg.etcd_cert_file)
        else:
            LOG.info("TLS disabled, using HTTP to connect to etcd.")
            _client = Etcd3Client(host=calico_cfg.etcd_host,
                                  port=calico_cfg.etcd_port,
                                  protocol="http")
    return _client


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


def _build_key(resource_kind, name):
    if _is_namespaced(resource_kind):
        # Use 'openstack' as the namespace.
        template = "/calico/resources/v3/projectcalico.org/%s/openstack/%s"
    else:
        template = "/calico/resources/v3/projectcalico.org/%s/%s"
    return template % (_plural(resource_kind).lower(), name)


def _get_with_metadata(resource_kind, name):
    client = _get_client()
    key = _build_key(resource_kind, name)
    results = client.get(key, metadata=True)
    LOG.debug("etcdv3 get key=%s results=%s", key, results)
    if len(results) != 1:
        raise etcd.EtcdKeyNotFound()
    value_as_string, item = results[0]
    value = json.loads(value_as_string)
    return value, item
