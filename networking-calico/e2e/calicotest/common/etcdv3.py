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

import logging

from etcd3gw.client import Etcd3Client
from etcd3gw.exceptions import Etcd3Exception
from etcd3gw.utils import _encode


LOG = logging.getLogger(__name__)
logging.getLogger(__name__).setLevel(logging.DEBUG)


class KeyNotFound(Etcd3Exception):
    pass


def get(key):
    """Read a value from etcdv3.

    - key (string): The key to read.

    Returns (value, mod_revision) where

    - value is the key's value

    - mod_revision is the etcdv3 revision at which the key was last
      modified.

    Raises KeyNotFound if there is no resource with that kind and name.
    """
    client = _get_client()
    results = client.get(key, metadata=True)
    LOG.debug("etcdv3 get key=%s results=%s", key, results)
    if len(results) != 1:
        raise KeyNotFound()
    value, item = results[0]
    return value, item["mod_revision"]


def put(key, value, mod_revision=None, lease=None, existing_value=None):
    """Write a key/value pair to etcdv3.

    - key (string): The key to write.

    - value (string): The value to write.

    - mod_revision (string): If specified, indicates that the write should only
      proceed if replacing an existing value with that mod_revision.
      mod_revision=0 indicates that the key must not yet exist, i.e. that this
      write will create it.

    - lease: If specified, a Lease object to associate with the key.

    - existing_value (string): If specified, indicates that the write should
      only proceed if replacing that existing value.

    Returns True if the write happened successfully; False if not.
    """
    client = _get_client()
    LOG.debug("etcdv3 put key=%s value=%s mod_revision=%r", key, value, mod_revision)
    txn = {}
    if mod_revision == 0:
        base64_key = _encode(key)
        txn["compare"] = [
            {
                "key": base64_key,
                "result": "EQUAL",
                "target": "VERSION",
                "version": 0,
            }
        ]
    elif mod_revision is not None:
        base64_key = _encode(key)
        txn["compare"] = [
            {
                "key": base64_key,
                "result": "EQUAL",
                "target": "MOD",
                "mod_revision": mod_revision,
            }
        ]
    elif existing_value is not None:
        base64_key = _encode(key)
        base64_existing = _encode(existing_value)
        txn["compare"] = [
            {
                "key": base64_key,
                "result": "EQUAL",
                "target": "VALUE",
                "value": base64_existing,
            }
        ]
    if txn:
        base64_value = _encode(value)
        txn["success"] = [
            {
                "request_put": {
                    "key": base64_key,
                    "value": base64_value,
                },
            }
        ]
        txn["failure"] = []
        if lease is not None:
            txn["success"][0]["request_put"]["lease"] = lease.id
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        succeeded = result.get("succeeded", False)
    else:
        succeeded = client.put(key, value, lease=lease)
    return succeeded


def delete(key, existing_value=None, mod_revision=None):
    """Delete a key/value pair from etcdv3.

    - key (string): The key to delete.

    - existing_value (string): If specified, indicates that the delete should
      only proceed if the existing value is this.

    - mod_revision (string): If specified, indicates that the delete should
      only proceed if deleting an existing value with that mod_revision.

    Returns True if the deletion was successful; False if not.
    """
    client = _get_client()
    LOG.debug("etcdv3 delete key=%s", key)
    if mod_revision is not None:
        base64_key = _encode(key)
        txn = {
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
                    "request_delete_range": {
                        "key": base64_key,
                    },
                }
            ],
            "failure": [],
        }
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        deleted = result.get("succeeded", False)
    elif existing_value is not None:
        base64_key = _encode(key)
        base64_existing = _encode(existing_value)
        txn = {
            "compare": [
                {
                    "key": base64_key,
                    "result": "EQUAL",
                    "target": "VALUE",
                    "value": base64_existing,
                }
            ],
            "success": [
                {
                    "request_delete_range": {
                        "key": base64_key,
                    },
                }
            ],
            "failure": [],
        }
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        deleted = result.get("succeeded", False)
    else:
        deleted = client.delete(key)
    LOG.debug("etcdv3 deleted=%s", deleted)
    return deleted


def get_prefix(prefix):
    """Read all etcdv3 data whose key begins with a given prefix.

    - prefix (string): The prefix.

    Returns a list of tuples (key, value, mod_revision), one for each key-value
    pair, in which:

    - key is the etcd key (a string)

    - value is the etcd value (also a string; note *not* JSON-decoded)

    - mod_revision is the revision at which that key was last modified (an
      integer represented as a string).

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
        t = (item["key"], value, item["mod_revision"])
        tuples.append(t)
    return tuples


def watch_once(key, timeout=None, **kwargs):
    """Watch a key and stop after the first event.

    :param key: key to watch
    :param timeout: (optional) timeout in seconds.
    :returns: event
    """
    client = _get_client()
    return client.watch_once(key, timeout=timeout, **kwargs)


# Internals.
_client = None


class EtcdAuthConfigurationMissing(Exception):
    pass


# Like Etcd3Client but adds an Authorization header to every request.
class Etcd3AuthClient(Etcd3Client):
    def __init__(
        self,
        host="localhost",
        port=2379,
        protocol="http",
        ca_cert=None,
        cert_key=None,
        cert_cert=None,
        timeout=None,
        username=None,
        password=None,
    ):
        super(Etcd3AuthClient, self).__init__(
            host=host,
            port=port,
            protocol=protocol,
            ca_cert=ca_cert,
            cert_key=cert_key,
            cert_cert=cert_cert,
            timeout=timeout,
            api_path="/v3beta/",
        )
        self.username = username
        self.password = password
        self.auth_token = None

    def post_with_auth_token(self, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if self.auth_token:
            headers["Authorization"] = self.auth_token
            kwargs["headers"] = headers
        return super(Etcd3AuthClient, self).post(*args, **kwargs)

    def authenticate(self):
        # Check that we have config for authentication.
        if not (self.username and self.password):
            raise EtcdAuthConfigurationMissing()

        # When authenticating, there mustn't be an Authorization
        # header with an old token, or else etcd responds with
        # "Unauthorized: invalid auth token".  So remove any
        # existing Authorization header.
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]

        # Send authenticate request.
        response = super(Etcd3AuthClient, self).post(
            self.get_url("/auth/authenticate"),
            json={"name": self.username, "password": self.password},
        )
        self.auth_token = response["token"]

        # Add Authorization header with the received token to the
        # underlying requests session.  This is needed for watches to
        # work, because the watch code does not use client.post and so
        # is not covered by the client.post overriding that we do in
        # this class.
        self.session.headers.update({"Authorization": response["token"]})

    def post(self, *args, **kwargs):
        try:
            return self.post_with_auth_token(*args, **kwargs)
        except Etcd3Exception as e:
            try:
                detail_text = e.detail.text
            except AttributeError:
                detail_text = ""
            LOG.info("Etcd3Exception: %r:\n%s", e, detail_text)
            # Authenticate and then reissue the request.
            self.authenticate()
            return self.post_with_auth_token(*args, **kwargs)


def _get_client():
    global _client
    if not _client:
        LOG.info("TLS disabled, using HTTP to connect to etcd.")
        _client = Etcd3AuthClient(
            host="controller",
            port=2379,
            protocol="http",
            username="calicouser",
            password="calicopasswd",
        )
    return _client
