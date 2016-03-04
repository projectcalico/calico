#!/usr/bin/python
import os
import time
import sys
import json
import Queue
import logging
from threading import Thread

import requests

import pycalico
from pycalico.datastore_datatypes import Rules, Rule
from pycalico.datastore_errors import MultipleEndpointsMatch
from pycalico.datastore import DatastoreClient

from handlers.network_policy import (add_update_network_policy,
                                     delete_network_policy)
from handlers.namespace import add_update_namespace, delete_namespace
from handlers.pod import add_update_pod, delete_pod

from constants import *

_log = logging.getLogger(__name__)


class PolicyAgent(object):
    def __init__(self):
        self._event_queue = Queue.Queue(maxsize=MAX_QUEUE_SIZE)
        """
        Queue to populate with events from API watches.
        """

        self.k8s_api = os.environ.get("K8S_API", DEFAULT_API)
        """
        Scheme, IP and port of the Kubernetes API.
        """

        self.auth_token = os.environ.get("K8S_AUTH_TOKEN", read_token_file())
        """
        Auth token to use when accessing the API.
        """
        _log.debug("Using auth token: %s", self.auth_token)

        self.ca_crt_exists = os.path.exists(CA_CERT_PATH)
        """
        True if a CA cert has been mounted by Kubernetes.
        """

        self._client = DatastoreClient()
        """
        Client for accessing the Calico datastore.
        """

        self._handlers = {}
        self.add_handler(RESOURCE_TYPE_NETWORK_POLICY, TYPE_ADDED,
                         add_update_network_policy)
        self.add_handler(RESOURCE_TYPE_NETWORK_POLICY, TYPE_DELETED,
                         delete_network_policy)
        self.add_handler(RESOURCE_TYPE_NAMESPACE, TYPE_ADDED,
                         add_update_namespace)
        self.add_handler(RESOURCE_TYPE_NAMESPACE, TYPE_DELETED,
                         delete_namespace)
        self.add_handler(RESOURCE_TYPE_POD, TYPE_ADDED,
                         add_update_pod)
        self.add_handler(RESOURCE_TYPE_POD, TYPE_DELETED,
                         delete_pod)
        """
        Handlers for watch events.
        """

    def add_handler(self, resource_type, event_type, handler):
        """
        Adds an event handler for the given event type (ADD, DELETE) for the
        given resource type.

        :param resource_type: The type of resource that this handles.
        :param event_type: The type of event that this handles.
        :param handler: The callable to execute when events are received.
        :return None
        """
        _log.info("Setting %s %s handler: %s",
                  resource_type, event_type, handler)
        key = (resource_type, event_type)
        self._handlers[key] = handler

    def get_handler(self, resource_type, event_type):
        """
        Gets the correct handler.

        :param resource_type: The type of resource that needs handling.
        :param event_type: The type of event that needs handling.
        :return None
        """
        key = (resource_type, event_type)
        _log.debug("Looking up handler for event: %s", key)
        return self._handlers[key]

    def run(self):
        """
        PolicyAgent.run() is called at program init to spawn watch threads,
        Loops to read responses from the Queue as they come in.
        """
        # Ensure the tier exists.
        self._client.set_policy_tier_metadata(NET_POL_TIER_NAME, 50)

        # Read initial state from Kubernetes API.
        self.read_initial_state()

        # Loop and read updates from the queue.
        self.read_updates()

    def read_initial_state(self):
        """
        Reads initial state from the API, processes existing resources, and
        kicks off threads to watch the Kubernetes API for changes.
        """
        resources = [RESOURCE_TYPE_NETWORK_POLICY,
                     RESOURCE_TYPE_NAMESPACE,
                     RESOURCE_TYPE_POD]
        for resource_type in resources:
            # Get existing resources from the API.
            _log.info("Getting existing %s objects", resource_type)
            get_url = GET_URLS[resource_type] % self.k8s_api
            resp = self._api_get(get_url, stream=False)
            _log.info("Response: %s", resp)

            # If we hit an error, raise it.  This will kill the agent,
            # which will be re-started by Kubernetes.
            if resp.status_code != 200:
                _log.error("Error querying API: %s", resp.json())
                raise Exception("Failed to query resource: %s" % resource_type)

            # Get the list of existing API objects from the response, as
            # well as the latest resourceVersion.
            resources = resp.json()["items"]
            metadata = resp.json().get("metadata", {})
            resource_version = metadata.get("resourceVersion")
            _log.debug("%s metadata: %s", resource_type, metadata)

            # Add the existing resources to the queue to be processed.
            _log.info("%s existing %s(s)", len(resources), resource_type)
            for resource in resources:
                _log.debug("Queueing update: %s", resource)
                update = (TYPE_ADDED, resource_type, resource)
                self._event_queue.put(update,
                                      block=True,
                                      timeout=QUEUE_PUT_TIMEOUT)

            # Start watching for updates from the last resourceVersion.
            watch_url = WATCH_URLS[resource_type] % self.k8s_api
            t = Thread(target=self._watch_api,
                       args=(watch_url, resource_version))
            t.daemon = True
            t.start()
            _log.info("Started watch on: %s", resource_type)

    def read_updates(self):
        """
        Reads from the update queue.

        An update on the queue must be a tuple of:
          (event_type, resource_type, resource)

        Where:
          - event_type: Either "ADDED", "MODIFIED", "DELETED"
          - resource_type: e.g "Namespace", "Pod", "NetworkPolicy"
          - resource: The parsed json resource from the API matching
                      the given resource_type.
        """
        while True:
            try:
                # Wait for an update on the event queue.
                _log.debug("Reading from event queue")
                update = self._event_queue.get(block=True)
                event_type, resource_type, resource = update
                self._event_queue.task_done()

                # We've recieved an update - process it.
                _log.debug("Read event: %s, %s, %s",
                           event_type,
                           resource_type,
                           json.dumps(resource, indent=2))
                self._process_update(event_type,
                                     resource_type,
                                     resource)
            except KeyError:
                # We'll hit this if we fail to parse an invalid update.
                _log.exception("Invalid update: %s", update)

    def _process_update(self, event_type, resource_type, resource):
        """
        Takes an event updates our state accordingly.
        """
        _log.debug("Processing '%s' for kind '%s'", event_type, resource_type)

        # Determine the key for this object using namespace and name.
        # This is simply used for easy identification in logs, etc.
        name = resource["metadata"]["name"]
        namespace = resource["metadata"].get("namespace")
        key = (namespace, name)

        # Treat "modified" as "added".
        if event_type == TYPE_MODIFIED:
            _log.debug("Treating 'MODIFIED' as 'ADDED'")
            event_type = TYPE_ADDED

        # Call the right handler.
        try:
            handler = self.get_handler(resource_type, event_type)
        except KeyError:
            _log.warning("No %s handlers for: %s",
                         event_type, resource_type)
        else:
            _log.debug("Calling handler: %s", handler)
            try:
                handler(key, resource)
            except KeyError:
                _log.exception("Invalid %s: %s", resource_type,
                               json.dumps(resource, indent=2))

    def _watch_api(self, path, resource_version=None):
        """
        Work loop for the watch thread.
        """
        _log.info("Starting watch on path: %s", path)
        while True:
            # Attempt to stream API resources.
            try:
                response = self._api_get(path,
                                         stream=True,
                                         resource_version=resource_version)
                _log.debug("Watch response for %s: %s", path, response)
            except requests.ConnectionError:
                _log.exception("Error querying path: %s", path)
                time.sleep(10)
                continue

            # Check for successful response.
            if response.status_code != 200:
                _log.error("Error watching path: %s", response.text)
                time.sleep(10)
                continue

            # Success - add resources to the queue for processing.
            for line in response.iter_lines():
                # Filter out keep-alive new lines.
                if line:
                    _log.debug("Read line: %s", line)
                    parsed = json.loads(line)
                    update = (parsed["type"],
                              parsed["object"]["kind"],
                              parsed["object"])
                    self._event_queue.put(update,
                                          block=True,
                                          timeout=QUEUE_PUT_TIMEOUT)

    def _api_get(self, path, stream, resource_version=None):
        """
        Get or stream from the API, given a resource.

        :param path: The API path to get.
        :param stream: Whether to return a single object or a stream.
        :param resource_version: The resourceVersion at which to
        start the stream.
        :return: A requests Response object
        """
        # Append the resource version - this indicates where the
        # watch should start.
        _log.info("Getting API resources '%s' at version '%s'. stream=%s",
                  path, resource_version, stream)
        if resource_version:
            path += "?resourceVersion=%s" % resource_version

        session = requests.Session()
        if self.auth_token:
            session.headers.update({'Authorization': 'Bearer ' + self.auth_token})
        verify = CA_CERT_PATH if self.ca_crt_exists else False
        return session.get(path, verify=verify, stream=stream)


def read_token_file():
    """
    Gets the API access token from the serviceaccount file.
    """
    file_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    _log.debug("Getting ServiceAccount token from: %s", file_path)
    if not os.path.exists(file_path):
        _log.warning("No ServiceAccount token found on disk")
        return None

    with open(file_path, "r") as f:
        token = f.read().replace('\n', '')
    _log.debug("Found ServiceAccount token: %s", token)
    return token


def configure_etc_hosts():
    """
    Reads the Kubernetes service environment variables and configures
    /etc/hosts accordingly.

    We need to do this for a combination of two reasons:
      1) When TLS is enabled, SSL verification requires that a hostname
         is used when initiating a connection.
      2) DNS lookups may fail at start of day, because this agent is
         responsible for allowing access to the DNS pod, but it must access
         the k8s API to do so, causing a dependency loop.
    """
    k8s_host = os.environ.get(K8S_SERVICE_HOST, "10.100.0.1")
    with open("/etc/hosts", "a") as f:
        f.write("%s    kubernetes.default" % k8s_host)
    _log.info("Appended 'kubernetes.default  -> %s' to /etc/hosts", k8s_host)


if __name__ == '__main__':
    # Configure logging.
    log_level = os.environ.get("LOG_LEVEL", "info").upper()
    formatter = logging.Formatter(LOG_FORMAT)
    stdout_hdlr = logging.StreamHandler(sys.stderr)
    stdout_hdlr.setFormatter(formatter)
    _log.addHandler(stdout_hdlr)
    _log.setLevel(log_level)

    # Configure /etc/hosts with Kubernetes API.
    _log.info("Configuring /etc/hosts")
    configure_etc_hosts()

    _log.info("Beginning execution")
    PolicyAgent().run()
