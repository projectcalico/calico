#!/usr/bin/python
import time
import sys
import json
import Queue
import logging
from threading import Thread

import requests

import pycalico
from pycalico.datastore_datatypes import Rules, Rule
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

# Resource types.
RESOURCE_TYPE_NETWORK_POLICY = "NetworkPolicy"
RESOURCE_TYPE_POD = "Pod"
RESOURCE_TYPE_NAMESPACE = "Namespace"

# API paths to NetworkPolicy objects.
NET_POLICY_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys"
NET_POLICY_WATCH_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/watch/networkpolicys"

# Mapping of resource to api URL.
GET_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/pods",
            RESOURCE_TYPE_NAMESPACE: "%s/api/v1/namespaces",
            RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_PATH}
WATCH_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/watch/pods",
              RESOURCE_TYPE_NAMESPACE: "%s/api/v1/watch/namespaces",
              RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_WATCH_PATH}

# Annotation to look for network-isolation on namespaces.
NS_POLICY_ANNOTATION = "net.alpha.kubernetes.io/network-isolation"

# Format to use for namespace profile names.
NS_PROFILE_FMT = "k8s_ns.%s"

# Format to use for labels inherited from a namespace. 
NS_LABEL_KEY_FMT = "k8s_ns/label/%s"

# Tier name to use for policies.
NET_POL_TIER_NAME = "k8s-network-policy"

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


class PolicyError(Exception):
    def __init__(self, msg=None, policy=None):
        Exception.__init__(self, msg)
        self.policy = policy


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
                         self._add_update_network_policy)
        self.add_handler(RESOURCE_TYPE_NETWORK_POLICY, TYPE_DELETED, 
                         self._delete_network_policy)
        self.add_handler(RESOURCE_TYPE_NAMESPACE, TYPE_ADDED, 
                         self._add_update_namespace)
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
        _log.debug("Looking up handler for event: %s", key)
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

            # If we hit an error, raise it.  This will kill the agent,
            # which will be re-started by Kubernetes.
            if resp.status_code != 200:
                _log.error("Error querying API: %s", resp.json())
                raise Exception("Failed to query resource: %s" % resource_type)

            # Get the list of existing API objects from the response, as 
            # well as the latest resourceVersion.
            updates = resp.json()["items"]
            metadata = resp.json().get("metadata", {})
            resource_version = metadata.get("resourceVersion")
            _log.debug("%s metadata: %s", resource_type, metadata)

            # Process the existing resources.
            _log.info("%s existing %s(s)", len(updates), resource_type)
            for update in updates:
                _log.debug("Processing existing resource: %s", 
                           json.dumps(update, indent=2))
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
        Takes an event updates our state accordingly.
        """
        _log.info("Processing '%s' for kind '%s'", event_type, resource_type) 

        # Determine the key for this object using namespace and name.
        # This is simply used for easy identification in logs, etc.
        name = resource["metadata"]["name"]
        namespace = resource["metadata"].get("namespace")
        key = (namespace, name)

        # Treat "modified" as "added".
        if event_type == TYPE_MODIFIED: 
            _log.info("Treating 'MODIFIED' as 'ADDED'")
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

    def _add_update_network_policy(self, key, policy):
        """
        Takes a new network policy from the Kubernetes API and 
        creates the corresponding Calico policy configuration.
        """
        _log.info("Adding new network policy: %s", key)
        
        # Ensure the tier exists.
        self._client.set_policy_tier_metadata(NET_POL_TIER_NAME, 50)

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

        # Determine the name for this policy.
        name = "%s.%s" % (policy["metadata"]["namespace"],
                          policy["metadata"]["name"])

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
        self._client.create_policy(NET_POL_TIER_NAME, name, 
                                   selector, order=10, rules=rules)
        _log.info("Updated policy '%s' for NetworkPolicy %s", name, key)

    def _delete_network_policy(self, key, policy):
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
            self._client.remove_policy(NET_POL_TIER_NAME, name)
        except KeyError:
            _log.info("Unable to find policy '%s' - already deleted", key)

    def _calculate_inbound_rules(self, policy):
        """
        Takes a NetworkPolicy object from the API and returns a list of 
        Calico Rules objects which should be applied on ingress.
        """
        _log.debug("Calculating inbound rules")

        # Store the rules to return.
        rules = []

        # Get this policy's namespace.
        policy_ns = policy["metadata"]["namespace"]

        # Iterate through each inbound rule and create the appropriate
        # rules.
        allow_incomings = policy["spec"].get("ingress") or []
        _log.info("Found %s ingress rules", len(allow_incomings))
        for r in allow_incomings:
            # If no "from" or "ports" keys are specified, we receive a 
            # null allow_incoming rule (rather than an empty dict).  Treat
            # this case as an empty dictionary.
            r = r or {}

            # Determine the destination ports to allow.  If no ports are
            # specified, allow all port / protocol combinations.
            _log.debug("Processing ingress rule: %s", r)
            ports_by_protocol = {}
            for to_port in r.get("ports") or []:
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
            for from_clause in r.get("from") or []:
                # We need to check if the key exists, not just if there is 
                # a non-null value.  The presence of the key with a null 
                # value means "select all".
                pods_present = "pods" in from_clause
                namespaces_present = "namespaces" in from_clause
                _log.debug("Is 'pods:' present? %s", pods_present)
                _log.debug("Is 'namespaces:' present? %s", namespaces_present)

                if pods_present and namespaces_present:
                    # This is an error case according to the API.
                    msg = "Policy API does not support both 'pods' and " \
                          "'namespaces' selectors."
                    raise PolicyError(msg, policy)
                elif pods_present:
                    # There is a pod selector in this "from" clause.
                    pod_selector = from_clause["pods"] or {}
                    _log.debug("Allow from pods: %s", pod_selector)
                    selectors = ["%s == '%s'" % (k,v) for k,v in pod_selector.iteritems()]

                    # We can only select on pods in this namespace.
                    selectors.append("%s == '%s'" % (K8S_NAMESPACE_LABEL, 
                                                   policy_ns))
                    selector = " && ".join(selectors)

                    # Append the selector to the from args.
                    _log.debug("Allowing pods which match: %s", selector)
                    from_args.append({"src_selector": selector})
                elif namespaces_present:
                    # There is a namespace selector.  Namespace labels are
                    # applied to each pod in the namespace using 
                    # the per-namespace profile.  We can select on namespace
                    # labels using the NS_LABEL_KEY_FMT modifier.
                    namespaces = from_clause["namespaces"] or {}
                    _log.debug("Allow from namespaces: %s", namespaces)
                    selectors = ["%s == '%s'" % (NS_LABEL_KEY_FMT % k, v) \
                            for k,v in namespaces.iteritems()]
                    selector = " && ".join(selectors)
                    if selector:
                        # Allow from the selected namespaces.
                        _log.debug("Allowing from namespaces which match: %s", 
                                    selector)
                        from_args.append({"src_selector": selector})
                    else:
                        # Allow from all pods in all namespaces.
                        _log.debug("Allowing from all pods in all namespaces")
                        selector = "has(%s)" % K8S_NAMESPACE_LABEL
                        from_args.append({"src_selector": selector})

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

    def _add_update_namespace(self, key, namespace):
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
        labels = namespace["metadata"].get("labels", {})
        for k, v in labels.iteritems():
            # Add a prefix to each label key to indicate this label
            # come from a namespace.
            labels[NS_LABEL_KEY_FMT % k] = v
            del labels[k]
        _log.debug("Generated namespace labels: %s", labels)

        # Create the Calico profile to represent this namespace, or 
        # update it if it already exists.  
        self._client.create_profile(profile_name, rules, labels)

        _log.info("Created/updated profile for namespace %s", namespace_name)

    def _delete_namespace(self, key, namespace):
        """
        Takes a deleted namespace and removes the corresponding
        configuration from the Calico datastore.
        """
        _log.info("Deleting namespace: %s", key)

        # Delete the Calico policy which represnets this namespace.
        namespace_name = namespace["metadata"]["name"]
        profile_name = NS_PROFILE_FMT % namespace_name
        try:
            self._client.remove_profile(profile_name)
        except KeyError:
            _log.info("Unable to find profile for namespace '%s'", key)

    def _add_update_pod(self, key, pod):
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
            endpoint = self._client.get_endpoint(
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
        self._client.set_endpoint(endpoint)
        _log.info("Updated labels on pod %s", key)

        # Configure this pod with its namespace profile.
        ns_profile = NS_PROFILE_FMT % namespace
        self._client.set_profiles_on_endpoint([ns_profile], 
                                              orchestrator_id="k8s",
                                              workload_id=endpoint.workload_id)

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
        Get or stream from the API, given a resource.
    
        :param resource: The resource you would like to watch.
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
    _log.info("Configuring /etc/hosts")
    configure_etc_hosts()

    try:
        _log.info("Beginning execution")
        PolicyAgent().run()
    except Exception:
        # Log the exception
        _log.exception("Unhandled Exception killed agent")
        raise
