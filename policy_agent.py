#!/usr/bin/python
import time
import sys
import json
import Queue
import logging
from threading import Thread

import requests

import pycalico
from pycalico.datastore_datatypes import Rules, Rule, GlobalPolicy
from pycalico.datastore_errors import (ProfileNotInEndpoint, 
                                       ProfileAlreadyInEndpoint,
                                       MultipleEndpointsMatch)
from pycalico.datastore import DatastoreClient
from cloghandler import ConcurrentRotatingFileHandler

_log = logging.getLogger(__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)

# Logging constants.
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'

# Default Kubernetes API value. 
DEFAULT_API = "https://kubernetes.default:443"

# Path to the CA certificate (if it exists).
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# API paths to NetworkPolicy objects.
NET_POLICY_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys"
NET_POLICY_WATCH_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/watch/networkpolicys"

# Resource types.
RESOURCE_TYPE_NETWORK_POLICY = "NetworkPolicy"
RESOURCE_TYPE_POD = "Pod"
RESOURCE_TYPE_NAMESPACE = "Namespace"

# Mapping of resource to api URL.
GET_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/pods",
            RESOURCE_TYPE_NAMESPACE: "%s/api/v1/namespaces",
            RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_PATH}
WATCH_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/watch/pods",
              RESOURCE_TYPE_NAMESPACE: "%s/api/v1/watch/namespaces",
              RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_WATCH_PATH}

# Annotation to look for network-isolation on namespaces.
NS_POLICY_ANNOTATION = "net.alpha.kubernetes.io/network-isolation"

# Groups to use for created policies.  Network policies are applied before 
# namespace policies based on the group.
NET_POL_GROUP_NAME = "50-k8s-net-policy"
NAMESPACE_GROUP_NAME = "60-k8s-namespace"

# Environment variables for getting the Kubernetes API.
K8S_SERVICE_PORT = "KUBERNETES_SERVICE_PORT"
K8S_SERVICE_HOST = "KUBERNETES_SERVICE_HOST"

# Label which represents the namespace a given pod belongs to.
K8S_NAMESPACE_LABEL = "calico/k8s_namespace"

# Update types.
TYPE_ADDED = "ADDED"
TYPE_MODIFIED = "MODIFIED"
TYPE_DELETED = "DELETED"
TYPE_ERROR = "ERROR"


class PolicyAgent():
    def __init__(self):
        self._event_queue = Queue.Queue()
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
                         self._add_new_network_policy)
        self.add_handler(RESOURCE_TYPE_NETWORK_POLICY, TYPE_DELETED, 
                         self._delete_network_policy)
        self.add_handler(RESOURCE_TYPE_NAMESPACE, TYPE_ADDED, 
                         self._add_new_namespace)
        self.add_handler(RESOURCE_TYPE_NAMESPACE, TYPE_DELETED, 
                         self._delete_namespace)
        self.add_handler(RESOURCE_TYPE_POD, TYPE_ADDED, 
                         self._add_update_pod)
        self.add_handler(RESOURCE_TYPE_POD, TYPE_DELETED, 
                         self._delete_pod)
        """
        Handlers for watch events.
        """
        
    def add_handler(self, resource_type, event_type, handler):
        """
        Adds an event handler for the given event type (ADD, DELETE) for the 
        given resource type.
        """
        _log.info("Setting %s %s handler: %s", 
                  resource_type, event_type, handler)
        key = (resource_type, event_type)
        self._handlers[key] = handler

    def get_handler(self, resource_type, event_type):
        """
        Gets the correct handler.
        """
        key = (resource_type, event_type)
        return self._handlers[key]

    def run(self):
        """
        PolicyAgent.run() is called at program init to spawn watch threads,
        Loops to read responses from the _watcher Queue as they come in.
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

            if resp.status_code != 200:
                _log.error("Error querying API: %s", resp.json())
                return
            updates = resp.json()["items"]
            metadata = resp.json().get("metadata", {})
            resource_version = metadata.get("resourceVersion")
            _log.debug("%s metadata: %s", resource_type, metadata)

            # Process the existing resources.
            _log.info("%s existing %s(s)", len(updates), resource_type)
            for update in updates:
                self._process_update(TYPE_ADDED, resource_type, update)

            # Start watching for updates from the last resourceVersion.
            watch_url = WATCH_URLS[resource_type] % self.k8s_api
            t = Thread(target=self._watch_api, 
                       args=(watch_url, resource_version))
            t.daemon = True
            t.start()
            _log.info("Started watch on: %s", resource_type)

        # Loop and read updates from the queue.
        _log.info("Reading from event queue")
        self.read_updates()

    def read_updates(self):
        """
        Reads from the update queue.
        """
        update = None

        while True:
            try:
                # There may be an update already, since we do a blocking get
                # in the `except Queue.Empty` block.  If we have an update, 
                # just process it before trying to read from the queue again.
                if not update:
                    _log.info("Non-blocking read from event queue")
                    update = self._event_queue.get(block=False)
                    self._event_queue.task_done()

                # We've recieved an update - process it.
                _log.debug("Read update from queue: %s", json.dumps(update, indent=2))
                self._process_update(update["type"], 
                                     update["object"]["kind"], 
                                     update["object"])
                update = None
            except Queue.Empty:
                _log.info("Queue empty, waiting for updates")
                update = self._event_queue.get(block=True)
            except KeyError:
                # We'll hit this if we fail to parse an invalid update.
                # Set update = None so we don't continue parsing the 
                # invalid update.
                _log.exception("Invalid update: %s", update)
                update = None
                time.sleep(10)

    def _process_update(self, event_type, resource_type, resource):
        """
        Takes an update from the queue and updates our state accordingly.
        """
        _log.info("Processing '%s' for kind '%s'", event_type, resource_type) 

        # Determine the key for this object.
        name = resource["metadata"]["name"]
        namespace = resource["metadata"].get("namespace")
        key = (namespace, name)

        # Get the right handler.
        try:
            handler = self.get_handler(resource_type, event_type) 
        except KeyError:    
            _log.warning("No delete %s handlers for: %s", 
                         event_type, resource_type)
        else:
            _log.debug("Calling handler: %s", handler)
            try:
                handler(key, resource)
            except KeyError:
                _log.exception("Invalid %s: %s", resource_type, 
                               json.dumps(resource, indent=2))

    def _add_new_network_policy(self, key, policy):
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
        selectors = ["%s == '%s'" % (k,v) for k,v in k8s_selector.iteritems()]
        selectors += ["%s == '%s'" % (K8S_NAMESPACE_LABEL, namespace)]
        selector = " && ".join(selectors)

        # Determine the name for this global policy.
        name = "net_policy-%s" % policy["metadata"]["name"]

        # Build the Calico rules.
        try:
            inbound_rules = self._calculate_inbound_rules(policy)
        except Exception:
            # It is possible bad rules will be passed - we don't want to 
            # crash the agent, but we do want to indicate a problem in the
            # logs, so that the policy can be fixed.
            _log.exception("Error parsing policy: %s", 
                           json.dumps(policy, indent=2))
            return
        else:
            rules =  Rules(id=name,
                           inbound_rules=inbound_rules,
                           outbound_rules=[Rule(action="allow")])

        # Create the network policy using the calculated selector and rules.
        self._client.create_global_policy(NET_POL_GROUP_NAME, name, selector, rules)
        _log.info("Updated global policy '%s' for NetworkPolicy %s", name, key)

    def _delete_network_policy(self, key, policy):
        """
        Takes a deleted network policy and removes the corresponding
        configuration from the Calico datastore.
        """
        _log.info("Deleting network policy: %s", key)

        # Determine the name for this global policy.
        name = "net_policy-%s" % policy["metadata"]["name"]

        # Delete the corresponding Calico policy 
        try:
            self._client.remove_global_policy(NET_POL_GROUP_NAME, name)
        except KeyError:
            pass

    def _calculate_inbound_rules(self, policy):
        """
        Takes a NetworkPolicy object from the API and returns a list of 
        Calico Rules objects which should be applied on ingress.
        """
        # Store the rules to return.
        rules = []

        # Iterate through each inbound rule and create the appropriate
        # rules.
        allow_incomings = policy["spec"]["inbound"]
        allow_incomings = allow_incomings or []
        for r in allow_incomings:
            # Determine the destination ports to allow.  If no ports are
            # specified, allow all port / protocol combinations.
            ports_by_protocol = {}
            for to_port in r.get("ports", []):
                # Keep a dict of ports exposed, keyed by protocol.
                protocol = to_port.get("protocol")
                port = to_port.get("port")
                ports = ports_by_protocol.setdefault(protocol, [])
                if port:
                    _log.debug("Allow to port: %s/%s", protocol, port)
                    ports.append(port)

            # Convert into arguments to be passed to a Rule object.
            to_args = []
            for protocol, ports in ports_by_protocol.iteritems():
                arg = {"protocol": protocol.lower()}
                if ports:
                    arg["dst_ports"] = ports
                to_args.append(arg)

            if not to_args:
                # There are not destination protocols / ports specified.
                # Allow to all protocols and ports.
                to_args = [{}]

            # Determine the from criteria.  If no "from" block is specified,
            # then we should allow from all sources.
            from_args = []
            for from_clause in r.get("from", []):
                pod_selector = from_clause.get("pods", {})
                namespaces = from_clause.get("namespaces", {})
                if pod_selector:
                    # There is a pod selector in this "from" clause.
                    _log.debug("Allow from pods: %s", pod_selector)
                    selectors = ["%s == '%s'" % (k,v) for k,v in pod_selector.iteritems()]
                    selector = " && ".join(selectors)
                    from_args.append({"src_selector": selector})
                elif namespaces:
                    _log.warning("'from: {namespaces: {}}' is not yet "
                                 "supported - ignoring %s", from_clause)

            if not from_args:
                # There are no match criteria specified.  We should allow
                # from all sources to the given ports.
                from_args = [{}]

            # A rule per-protocol, per-from-clause.
            for to_arg in to_args: 
                for from_arg in from_args:
                    # Create a rule by combining a 'from' argument with
                    # the protocol / ports arguments.
                    from_arg.update(to_arg)
                    from_arg.update({"action": "allow"})
                    rules.append(Rule(**from_arg))

        _log.debug("Calculated rules: %s", rules)
        return rules

    def _add_new_namespace(self, key, namespace):
        """
        Takes a new namespace from the Kubernetes API and 
        creates the corresponding Calico policy configuration.
        """
        _log.info("Adding new namespace: %s", key)

        # Determine the type of network-isolation specified by this namespace.
        # This defaults to no isolation.
        annotations = namespace["metadata"].get("annotations", {})
        _log.debug("Namespace %s has annotations: %s", key, annotations)
        net_isolation = annotations.get(NS_POLICY_ANNOTATION, "no") == "yes"
        _log.info("Namespace %s has: network-isolation=%s", key, net_isolation)

        # Determine the policy name to create.
        namespace_name = namespace["metadata"]["name"]
        policy_name = "k8s_ns-%s" % namespace_name

        # Determine the rules to use.
        outbound_rules = [Rule(action="allow")]
        if net_isolation:
            inbound_rules = [Rule(action="deny")]
        else:
            inbound_rules = [Rule(action="allow")]
        rules = Rules(id=policy_name,
                      inbound_rules=inbound_rules,
                      outbound_rules=outbound_rules)

        # Create the Calico policy to represent this namespace, or 
        # update it if it already exists.  Namespace policies select each
        # pod within that namespace.
        selector = "%s == '%s'" % (K8S_NAMESPACE_LABEL, namespace_name) 
        self._client.create_global_policy(NAMESPACE_GROUP_NAME, policy_name, 
                                          selector, rules=rules)
        _log.info("Created/updated global policy for namespace %s", 
                  namespace_name)

    def _delete_namespace(self, key, namespace):
        """
        Takes a deleted namespace and removes the corresponding
        configuration from the Calico datastore.
        """
        _log.info("Deleting namespace: %s", key)

        # Delete the Calico policy which represnets this namespace.
        # We need to make sure that there are no pods running 
        # in this namespace first.
        namespace_name = namespace["metadata"]["name"]
        policy_name = "k8s_ns-%s" % namespace_name
        try:
            self._client.remove_global_policy(NAMESPACE_GROUP_NAME, policy_name)
        except KeyError:
            pass

    def _add_update_pod(self, key, pod):
        """
        Takes a new or updated pod from the Kubernetes API and 
        creates the corresponding Calico configuration.
        """
        _log.info("Adding new pod: %s", key)

        # Get the Calico endpoint.  This may or may not have already been 
        # created by the CNI plugin.  If it hasn't been created, we need to 
        # wait until is has before we can do any meaningful work.
        workload_id = "%s.%s" % (pod["metadata"]["namespace"],
                                 pod["metadata"]["name"])
        try:
            _log.debug("Looking for endpoint that matches workload_id=%s",
                       workload_id)
            endpoint = self._client.get_endpoint(
                orchestrator_id="cni",
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

        # Add a special label for the Kubernetes namespace.
        labels[K8S_NAMESPACE_LABEL] = pod["metadata"]["namespace"]

        # Set the labels on the endpoint.
        endpoint.labels = labels
        self._client.set_endpoint(endpoint)
        _log.info("Updated labels on pod %s", key)

        # Remove the 'deny-inbound' profile from the pod now that 
        # it has been configured with labels.  It will match at least the 
        # per-namespace policy, and potentially others, which will 
        # define what connectivity is allowed.
        #self._client.set_profiles_on_endpoint([], 
        #                                      orchestrator_id="cni",
        #                                      workload_id=endpoint.workload_id)

    def _delete_pod(self, key, pod):
        """
        We don't need to do anything when a pod is deleted - the CNI plugin
        handles the deletion of the endpoint.
        """
        _log.info("Pod deleted: %s", key)

    def _watch_api(self, path, resource_version=None):
        try:
            self.__watch_api(path, resource_version)
        except Exception:
            _log.exception("Exception watching %s", path)

    def __watch_api(self, path, resource_version=None):
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
                _log.info("Watch response for %s: %s", path, response)
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
                    _log.debug("Adding line to queue: %s", line)
                    self._event_queue.put(json.loads(line))

    def _api_get(self, path, stream, resource_version=None):
        """
        Watch a stream from the API given a resource.
    
        :param resource: The plural resource you would like to watch.
        :return: A stream of json objs e.g. {"type": "MODIFED"|"ADDED"|"DELETED", "object":{...}}
        :rtype stream
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
        _log.info("No ServiceAccount token found on disk") 
        return None

    with open(file_path, "r") as f:
        token = f.read().replace('\n', '')
    _log.debug("Found ServiceAccount token: %s", token) 
    return token


def configure_etc_hosts():
    """
    Reads the Kubernetes service environment variables and configures
    /etc/hosts accordingly.
    """
    k8s_host = os.environ.get(K8S_SERVICE_HOST, "10.100.0.1")
    with open("/etc/hosts", "a") as f:
        f.write("%s    kubernetes.default" % k8s_host)
    _log.info("Appended 'kubernetes.default  -> %s' to /etc/hosts", k8s_host)


if __name__ == '__main__':
    # Configure logging.
    log_file = "/var/log/calico/kubernetes/policy/agent.log"
    log_level = os.environ.get("LOG_LEVEL", "info").upper()
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))
    formatter = logging.Formatter(LOG_FORMAT)
    file_hdlr = ConcurrentRotatingFileHandler(filename=log_file,
                                              maxBytes=1000000,
                                              backupCount=5)
    file_hdlr.setFormatter(formatter)
    _log.addHandler(file_hdlr)
    _log.setLevel(log_level)

    # Log to stderr as well.
    stdout_hdlr = logging.StreamHandler(sys.stderr)
    stdout_hdlr.setLevel(log_level)
    stdout_hdlr.setFormatter(formatter)
    _log.addHandler(stdout_hdlr)

    # Configure /etc/hosts with Kubernetes API.
    configure_etc_hosts()

    try:
        PolicyAgent().run()
    except Exception:
        # Log the exception
        _log.exception("Unhandled Exception killed agent")
        raise
