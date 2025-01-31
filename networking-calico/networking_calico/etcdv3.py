# -*- coding: utf-8 -*-
# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

import functools
from importlib.metadata import version
from packaging.version import Version

from etcd3gw.client import Etcd3Client
from etcd3gw.exceptions import Etcd3Exception
from etcd3gw.lease import Lease
from etcd3gw.utils import _encode
from etcd3gw.utils import _increment_last_byte

from networking_calico.compat import cfg
from networking_calico.compat import log

# Incantations for enabling oslo_log debug logging, when desired:
# log.register_options(cfg.CONF)
# cfg.CONF.debug = True
# cfg.CONF.use_stderr = True
# log.setup(cfg.CONF, "demo")

LOG = log.getLogger(__name__)

# Limit on number of keys we get from etcd.  We found that the etcd gateway
# has limits on the size of responses that kick in at 3000+ keys so make sure
# we leave plenty of headroom.
CHUNK_SIZE_LIMIT = 200

# Indicates that a put operation must update an existing resource and not
# create a new resource.
MUST_UPDATE = "MUST_UPDATE"


class KeyNotFound(Etcd3Exception):
    pass


def get(key, with_lease=False):
    """Read a value from etcdv3.

    - key (string): The key to read.

    - with_lease (boolean): Indicates also to return the key's lease.

    Returns (value, mod_revision) or (value, mod_revision, lease) where

    - value is the key's value

    - mod_revision is the etcdv3 revision at which the key was last
      modified

    - lease is an etcd3gw.lease.Lease object representing the key's lease, if
      it has one; or else None.

    Raises KeyNotFound if there is no resource with that kind and name.
    """
    client = _get_client()
    results = client.get(key, metadata=True)
    LOG.debug("etcdv3 get key=%s results=%s", key, results)
    if len(results) != 1:
        raise KeyNotFound()
    value, item = results[0]
    value = value.decode()
    if with_lease:
        lease = None
        if 'lease' in item:
            lease = Lease(int(item['lease']), client)
        return value, item['mod_revision'], lease
    else:
        return value, item['mod_revision']


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
    LOG.debug("etcdv3 put key=%s value=%s mod_revision=%r",
              key, value, mod_revision)
    txn = {}
    if mod_revision == 0:
        # Write operation must _create_ the KV entry.
        base64_key = _encode(key)
        txn['compare'] = [{
            'key': base64_key,
            'result': 'EQUAL',
            'target': 'VERSION',
            'version': 0,
        }]
    elif mod_revision == MUST_UPDATE:
        # Write operation must update and _not_ create the KV entry.
        base64_key = _encode(key)
        txn['compare'] = [{
            'key': base64_key,
            'result': 'NOT_EQUAL',
            'target': 'VERSION',
            'version': 0,
        }]
    elif mod_revision is not None:
        # Write operation must _replace_ a KV entry with the specified
        # revision.
        base64_key = _encode(key)
        txn['compare'] = [{
            'key': base64_key,
            'result': 'EQUAL',
            'target': 'MOD',
            'mod_revision': mod_revision,
        }]
    elif existing_value is not None:
        # Write operation must _replace_ a KV entry with the specified value.
        base64_key = _encode(key)
        base64_existing = _encode(existing_value)
        txn['compare'] = [{
            'key': base64_key,
            'result': 'EQUAL',
            'target': 'VALUE',
            'value': base64_existing,
        }]
    if txn:
        base64_value = _encode(value)
        txn['success'] = [{
            'request_put': {
                'key': base64_key,
                'value': base64_value,
            },
        }]
        txn['failure'] = []
        if lease is not None:
            txn['success'][0]['request_put']['lease'] = lease.id
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        succeeded = result.get('succeeded', False)
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
            'compare': [{
                'key': base64_key,
                'result': 'EQUAL',
                'target': 'MOD',
                'mod_revision': mod_revision,
            }],
            'success': [{
                'request_delete_range': {
                    'key': base64_key,
                },
            }],
            'failure': [],
        }
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        deleted = result.get('succeeded', False)
    elif existing_value is not None:
        base64_key = _encode(key)
        base64_existing = _encode(existing_value)
        txn = {
            'compare': [{
                'key': base64_key,
                'result': 'EQUAL',
                'target': 'VALUE',
                'value': base64_existing,
            }],
            'success': [{
                'request_delete_range': {
                    'key': base64_key,
                },
            }],
            'failure': [],
        }
        result = client.transaction(txn)
        LOG.debug("transaction result %s", result)
        deleted = result.get('succeeded', False)
    else:
        deleted = client.delete(key)
    LOG.debug("etcdv3 deleted=%s", deleted)
    return deleted


def delete_prefix(prefix):
    """Best effort deletion of all keys beginning with PREFIX."""
    LOG.debug("etcdv3 delete_prefix prefix=%s", prefix)
    client = _get_client()
    return client.delete_prefix(prefix)


def get_prefix(prefix, revision=None):
    """Read all etcdv3 data whose key begins with a given prefix.

    - prefix (string): The prefix.

    - revision: The revision to do the get at.  If not specified then the
      current revision is used.

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

    if revision is None:
        _, revision = get_status()
        LOG.debug("Doing get at current revision: %r", revision)

    # The JSON gateway can only return a certain number of bytes in a single
    # response so we chunk up the read into blocks.
    #
    # Since etcd's get protocol has an inclusive range_start and an exclusive
    # range_end, we load the keys in reverse order.  That way, we can use the
    # final key in each chunk as the next range_end.
    range_end = _encode(_increment_last_byte(prefix))
    results = []
    while True:
        # Note: originally, we included the sort_target parameter here but
        # etcdgw has a bug (https://github.com/dims/etcd3-gateway/issues/18),
        # which prevents that from working.  In any case, sort-by-key is the
        # default, which is what we want.
        chunk = client.get(prefix,
                           metadata=True,
                           range_end=range_end,
                           sort_order='descend',
                           limit=CHUNK_SIZE_LIMIT,
                           revision=str(revision))
        results.extend(chunk)
        if len(chunk) < CHUNK_SIZE_LIMIT:
            # Partial (or empty) chunk signals that we're done.
            break
        _, data = chunk[-1]
        range_end = _encode(data["key"])

    LOG.debug("etcdv3 get_prefix %s results=%s", prefix, len(results))
    tuples = []
    for result in results:
        value, item = result
        t = (item['key'].decode(), value.decode(), item['mod_revision'])
        tuples.append(t)
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
    LOG.debug("Watch subtree %s from revision %r", prefix, start_revision)
    client = _get_client()
    event_stream, cancel = client.watch_prefix(prefix,
                                               start_revision=start_revision)
    return event_stream, cancel


def get_status():
    """Get the current etcdv3 cluster ID and revision.

    Returns a tuple (cluster_id, revision).
    """
    client = _get_client()
    status = client.status()
    LOG.debug("etcdv3 status %s", status)
    return status['header']['cluster_id'], status['header']['revision']


def request_compaction(revision):
    """Request compaction at the specified revision."""
    client = _get_client()
    LOG.debug("request etcdv3 compaction at %r", revision)
    response = client.post(client.get_url("/kv/compaction"),
                           json={"revision": str(revision)})
    LOG.debug("=> %s", response)


def watch_once(key, timeout=None, **kwargs):
    """Watch a key and stop after the first event.

    :param key: key to watch
    :param timeout: (optional) timeout in seconds.
    :returns: event
    """
    client = _get_client()
    LOG.debug("etcdv3 watch_once %s timeout %r kwargs %r",
              key, timeout, kwargs)
    return client.watch_once(key, timeout=timeout, **kwargs)


def get_lease(ttl):
    """Get a lease for the specified TTL (in seconds)."""
    client = _get_client()
    return client.lease(ttl=ttl)


def logging_exceptions(fn):
    """Decorator to log (and reraise) Etcd3Exceptions."""
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except Etcd3Exception as e:
            LOG.warning("Etcd3Exception, re-raising: %r:\n%s",
                        e, e.detail_text)
            raise
    return wrapped


# Internals.
_client = None


# Possible API paths for connecting to an etcd server.  Defined as a variable
# here so that test code can override it after importing this file.
_possible_etcd_api_paths = ['/v3/', '/v3beta/', '/v3alpha/']


# Wrap Etcd3Client to authenticate when needed and add an
# Authorization header to the session headers.
#
# All of networking-calico's etcd operations go through either (1)
# etcd3gw.client.Etcd3Client.post, or (2) etcd3gw.watch.Watcher.
# Here, we hook (1) so as to authenticate when the normal POST request
# fails; then we add the returned auth token as an Authorization
# header on the underlying session.  Adding that header to the session
# means that it will apply to etcd3gw.watch.Watcher, as well as to
# POST requests for all non-watch operations.
#
# The question arises what happens if we do a watch operation before
# there is correct Authorization on the session?  Firstly this is
# unlikely, because we always watch following a preceding get of the
# same key or subtree; but it might still be possible if the etcd
# server is restarted after the get and before the watch.  Secondly,
# we handle the watch request failing and loop round to retry the get
# again.  Overall, therefore, we are safe on this point.
class Etcd3AuthClient(Etcd3Client):
    def __init__(self, host='localhost', port=2379, protocol="http",
                 ca_cert=None, cert_key=None, cert_cert=None, timeout=None,
                 username=None, password=None):
        global _possible_etcd_api_paths
        possible_api_paths = _possible_etcd_api_paths
        created_working_client = False
        while not created_working_client:
            try:
                LOG.info("Try creating etcd3gw client with %s",
                         possible_api_paths[0])
                super(Etcd3AuthClient, self).__init__(
                    host=host,
                    port=port,
                    protocol=protocol,
                    ca_cert=ca_cert,
                    cert_key=cert_key,
                    cert_cert=cert_cert,
                    timeout=timeout,
                    api_path=possible_api_paths[0])
                possible_api_paths = possible_api_paths[1:]
            except TypeError:
                # Indicates an old version of etcd3gw that doesn't support the
                # api_path keyword.
                possible_api_paths = []
                super(Etcd3AuthClient, self).__init__(
                    host=host,
                    port=port,
                    protocol=protocol,
                    ca_cert=ca_cert,
                    cert_key=cert_key,
                    cert_cert=cert_cert,
                    timeout=timeout)

            self.username = username
            self.password = password

            # Now test if this client is really working.
            try:
                status = self.status()
                LOG.info("Status = %r", status)
                created_working_client = True
            except Exception:
                LOG.exception("etcd3gw client not working")
                # If there are no more possible API paths to try, reraise the
                # current exception.
                if not possible_api_paths:
                    raise

    def authenticate(self):
        # When authenticating, there mustn't be an Authorization
        # header with an old token, or else etcd responds with
        # "Unauthorized: invalid auth token".  So remove any existing
        # Authorization header.
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

        # Send authenticate request.  If this raises an exception,
        # e.g. because of a connectivity issue to the etcd server,
        # it's OK for that to bubble up and be handled in the code
        # that called post.
        response = super(Etcd3AuthClient, self).post(
            self.get_url('/auth/authenticate'),
            json={"name": self.username, "password": self.password}
        )

        # Add Authorization header with the received token to the
        # underlying requests session.  This covers all subsequent
        # requests, and is needed in particular for watches, because
        # the watch code does not use client.post and so could not be
        # covered by adding a header to kwargs in the following post
        # method.
        self.session.headers['Authorization'] = response['token']

    def post(self, *args, **kwargs):
        if Version(version("etcd3gw")) < Version("2.4.0"):
            # Impose a maximum timeout, according to the [calico]
            # etcd_timeout config parameter.  Imposing a timeout is
            # generally a good idea, and specifically we want to protect
            # this code from the apparent etcdserver hang bug at
            # https://github.com/etcd-io/etcd/issues/11377.
            if 'timeout' not in kwargs or \
               kwargs['timeout'] > cfg.CONF.calico.etcd_timeout:
                kwargs['timeout'] = cfg.CONF.calico.etcd_timeout
        try:
            # Try the post.  If no authentication is needed, or if an
            # Authorization token has been added to the session's
            # headers, and is still valid, this should succeed.
            return super(Etcd3AuthClient, self).post(*args, **kwargs)
        except Etcd3Exception as e:
            if self.username and self.password:
                # Etcd auth credentials are configured, so assume the
                # problem might be that we need to authenticate or
                # re-authenticate.
                LOG.info("Might need to (re)authenticate: %r:\n%s",
                         e, e.detail_text)

                # Authenticate and then reissue the request.
                self.authenticate()
                return super(Etcd3AuthClient, self).post(*args, **kwargs)

            # Otherwise re-raise.
            raise


def _get_client():
    global _client
    if not _client:
        calico_cfg = cfg.CONF.calico
        tls_config_params = [
            calico_cfg.etcd_key_file,
            calico_cfg.etcd_cert_file,
            calico_cfg.etcd_ca_cert_file,
        ]
        # Impose a maximum timeout, according to the [calico] etcd_timeout
        # config parameter.  Imposing a timeout is generally a good idea, and
        # specifically we want to protect this code from the apparent
        # etcdserver hang bug at https://github.com/etcd-io/etcd/issues/11377.
        # etcd3gw 1.0.1 and 2.4.0 both allow specifying a timeout on the
        # following client constructors, but the timeout only actually works in
        # 2.4.0 onwards.  For etcd3gw<=2.4.0 we work around that by also
        # specifying the timeout as a kwarg on each post() call.
        if any(tls_config_params):
            LOG.info("TLS to etcd is enabled with key file %s; "
                     "cert file %s; CA cert file %s", *tls_config_params)
            _client = Etcd3AuthClient(host=calico_cfg.etcd_host,
                                      port=calico_cfg.etcd_port,
                                      timeout=cfg.CONF.calico.etcd_timeout,
                                      protocol="https",
                                      ca_cert=calico_cfg.etcd_ca_cert_file,
                                      cert_key=calico_cfg.etcd_key_file,
                                      cert_cert=calico_cfg.etcd_cert_file,
                                      username=calico_cfg.etcd_username,
                                      password=calico_cfg.etcd_password)
        else:
            LOG.info("TLS disabled, using HTTP to connect to etcd.")
            _client = Etcd3AuthClient(host=calico_cfg.etcd_host,
                                      port=calico_cfg.etcd_port,
                                      timeout=cfg.CONF.calico.etcd_timeout,
                                      protocol="http",
                                      username=calico_cfg.etcd_username,
                                      password=calico_cfg.etcd_password)
    return _client
