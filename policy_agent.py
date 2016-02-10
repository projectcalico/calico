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
LOG_LEVEL=logging.DEBUG
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'

# API path to get NetworkPolicy objects.
NET_POLICY_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys"
NET_POLICY_WATCH_PATH = "%s/apis/net.alpha.kubernetes.io/v1alpha1/watch/networkpolicys"

# API paths to get Pod objects.
POD_WATCH_PATH = "%s/api/v1/watch/pods"

# API paths to get namespaces.
NAMESPACE_WATCH_PATH = "%s/api/v1/watch/namespaces"

# Annotation to look for network-isolation on namespaces.
NS_POLICY_ANNOTATION = "net.alpha.kubernetes.io/network-isolation"

# Groups to use for created policies.  Network policies are applied before 
# namespace policies based on the group.
NET_POL_GROUP_NAME = "50-k8s-net-policy"
NAMESPACE_GROUP_NAME = "60-k8s-namespace"

K8S_NAMESPACE_LABEL = "calico/k8s_namespace"

# Resource types.
RESOURCE_TYPE_NETWORK_POLICY = "NetworkPolicy"
RESOURCE_TYPE_POD = "Pod"
RESOURCE_TYPE_NAMESPACE = "Namespace"

# Update types.
TYPE_ADDED = "ADDED"
TYPE_MODIFIED = "MODIFIED"
TYPE_DELETED = "DELETED"
TYPE_ERROR = "ERROR"
VALID_COMMANDS = [TYPE_ADDED, TYPE_MODIFIED, TYPE_DELETED]


class PolicyAgent():
    def __init__(self):
        self._event_queue = Queue.Queue()
        """
        Queue to populate with events from API watches.
        """

        self.k8s_api = os.environ.get("K8S_API", "https://10.100.0.1:443")
        """
        Scheme, IP and port of the Kubernetes API.
        """

        self.auth_token = os.environ.get("K8S_AUTH_TOKEN")
        """
        Auth token to use when accessing the API.
        """

        path = NET_POLICY_WATCH_PATH % self.k8s_api
        self._network_policy_thread = Thread(target=self._watch_api, 
                                             args=(path,))
        self._network_policy_thread.daemon = True
        """
        Thread which performs watch of Kubernetes API for changes to 
        NetworkPolicy objects.
        """

        path = NAMESPACE_WATCH_PATH % self.k8s_api
        self._namespace_thread = Thread(target=self._watch_api, 
                                             args=(path,))
        self._namespace_thread.daemon = True
        """
        Thread which performs watch of Kubernetes API for changes to 
        Namespace objects.
        """

        path = POD_WATCH_PATH % self.k8s_api
        self._pod_thread = Thread(target=self._watch_api, 
                                  args=(path,))
        self._pod_thread.daemon = True
        """
        Thread which performs watch of Kubernetes API for changes to 
        Pod objects.
        """

        self._client = DatastoreClient()
        """
        Client for accessing the Calico datastore.
        """

        self._network_policies = {}
        self._namespaces = {}
        self._pods = {}
        """
        Store internal state.
        """

    def run(self):
        """
        PolicyAgent.run() is called at program init to spawn watch threads,
        Loops to read responses from the _watcher Queue as they come in.
        """
        # Start threads to watch Kubernetes API. 
        _log.info("Starting API watch on: NetworkPolicy, Pod, Namespace")
        self._network_policy_thread.start()
        self._namespace_thread.start()
        self._pod_thread.start()

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
                self._process_update(update)
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

    def _process_update(self, update):
        """
        Takes an update from the queue and updates our state accordingly.
        """
        # Parse out the type of update and resource.
        update_type = update["type"]
        resource_type = update["object"]["kind"] 
        _log.info("Processing '%s' for kind '%s'", update_type, resource_type) 

        # Determine the key for this object.
        if resource_type == RESOURCE_TYPE_NAMESPACE:
            # Namespaces are just keyed off of their name.
            name = update["object"]["metadata"]["name"]
            key = (name,)
        else:
            # Objects are keyed off their name and namespace.
            name = update["object"]["metadata"]["name"]
            namespace = update["object"]["metadata"]["namespace"]
            key = (namespace, name)

        if resource_type == RESOURCE_TYPE_NETWORK_POLICY:
            # NetworkPolicy objects correspond directly to Calico
            # profiles - create, delete or update the corresponding Calico 
            # profile for each NetworkPolicy update. 
            if update_type in [TYPE_ADDED, TYPE_MODIFIED]:
                # Add or update network policy.
                self._add_new_network_policy(key, update)
            else:
                # Delete an existing network policy.
                assert update_type == TYPE_DELETED
                try:
                    self._delete_network_policy(key, update)
                except KeyError:
                    _log.warning("Delete for unknown network policy: %s", key)
        elif resource_type == RESOURCE_TYPE_NAMESPACE:
            # Namespaces correspond directly to Calico profiles. 
            if update_type in [TYPE_ADDED, TYPE_MODIFIED]:
                # Add or update network policy.
                self._add_new_namespace(key, update)
            else:
                # Delete an existing network policy.
                assert update_type == TYPE_DELETED
                try:
                    self._delete_namespace(key, update)
                except KeyError:
                    _log.warning("Delete for unknown namespace: %s", key)
        elif resource_type == RESOURCE_TYPE_POD:
            # Pods have policy applied to them using Namespaces and
            # NetworkPolicy objects.  We must update the corresponding 
            # endpoints in the Calico datastore to have the correct 
            # labels applied.
            if update_type in [TYPE_ADDED, TYPE_MODIFIED]:
                # Add or update pod.
                self._add_update_pod(key, update)
            else:
                assert update_type == TYPE_DELETED
                try:
                    self._delete_pod(key, update)
                except KeyError:
                    _log.warning("Delete for unknown pod: %s", key)

    def _add_new_network_policy(self, key, policy):
        """
        Takes a new network policy from the Kubernetes API and 
        creates the corresponding Calico policy configuration.
        """
        _log.info("Adding new network policy: %s", key)
        self._network_policies[key] = policy

        # Parse this network policy so we can convert it to the appropriate
        # Calico policy.  First, get the selector from the API object.
        k8s_selector = policy["object"]["spec"]["applyTo"]

        # Build the appropriate Calico label selector.  This is done using 
        # the labels provided in the NetworkPolicy, as well as the 
        # NetworkPolicy's namespace.
        namespace = policy["object"]["metadata"]["namespace"]
        selectors = ["%s == '%s'" % (k,v) for k,v in k8s_selector.iteritems()]
        selectors += ["%s == '%s'" % (K8S_NAMESPACE_LABEL, namespace)]
        selector = " && ".join(selectors)

        # Determine the name for this global policy.
        name = "net_policy-%s" % policy["object"]["metadata"]["name"]

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

        # Delete from internal dict.
        del self._network_policies[key]

        # Determine the name for this global policy.
        name = "net_policy-%s" % policy["object"]["metadata"]["name"]

        # Delete the corresponding Calico policy 
        self._client.remove_global_policy(NET_POL_GROUP_NAME, name)

    def _calculate_inbound_rules(self, policy):
        """
        Takes a NetworkPolicy object from the API and returns a list of 
        Calico Rules objects which should be applied on ingress.
        """
        # Store the rules to return.
        rules = []

        # Iterate through each allowIncoming object and create the appropriate
        # rules.
        allow_incomings = policy["object"]["spec"]["allowIncoming"]
        for r in allow_incomings:
            # Determine the destination ports to allow.  If no ports are
            # specified, allow all port / protocol combinations.
            ports_by_protocol = {}
            for to_port in r.get("toPorts", []):
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

        # Store the namespace.
        self._namespaces[key] = namespace 

        # Determine the type of network-isolation specified by this namespace.
        # This defaults to no isolation.
        annotations = namespace["object"]["metadata"].get("annotations", {})
        _log.debug("Namespace %s has annotations: %s", key, annotations)
        net_isolation = annotations.get(NS_POLICY_ANNOTATION, "no") == "yes"
        _log.info("Namespace %s has: network-isolation=%s", key, net_isolation)

        # Determine the policy name to create.
        namespace_name = namespace["object"]["metadata"]["name"]
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
        namespace_name = namespace["object"]["metadata"]["name"]
        policy_name = "k8s_ns-%s" % namespace_name
        self._client.remove_global_policy(NAMESPACE_GROUP_NAME, policy_name)

        # Delete from internal dict.
        del self._namespaces[key]

    def _add_update_pod(self, key, pod):
        """
        Takes a new or updated pod from the Kubernetes API and 
        creates the corresponding Calico configuration.
        """
        _log.info("Adding new pod: %s", key)

        # Store the latest version of the API Pod.
        self._pods[key] = pod 

        # Get the Calico endpoint.  This may or may not have already been 
        # created by the CNI plugin.  If it hasn't been created, we need to 
        # wait until is has before we can do any meaningful work.
        workload_id = "%s.%s" % (pod["object"]["metadata"]["namespace"],
                                 pod["object"]["metadata"]["name"])
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
        labels = pod["object"]["metadata"].get("labels", {}) 
        _log.debug("Pod '%s' has labels: %s", key, labels)

        # Add a special label for the Kubernetes namespace.
        labels[K8S_NAMESPACE_LABEL] = pod["object"]["metadata"]["namespace"]

        # Set the labels on the endpoint.
        endpoint.labels = labels
        self._client.set_endpoint(endpoint)
        _log.info("Updated labels on pod %s", key)

        # Remove the 'deny-inbound' profile from the pod now that 
        # it has been configured with labels.  It will match at least the 
        # per-namespace policy, and potentially others, which will 
        # define what connectivity is allowed.
        self._client.set_profiles_on_endpoint([], 
                                              orchestrator_id="cni",
                                              workload_id=endpoint.workload_id)

    def _delete_pod(self, key, pod):
        """
        Takes a deleted pod and removes the corresponding
        configuration from the Calico datastore.
        """
        _log.info("Deleting pod: %s", key)

        # Delete from internal dict.
        del self._pods[key]

    def _watch_api(self, path, resource_version=None):
        """
        Work loop for the watch thread.
        """
        _log.info("Starting watch on path: %s", path)
        while True:
            # Attempt to stream API resources.
            try:
                response = self._get_api_stream(path, resource_version)
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

    def _get_api_stream(self, path, resource_version=None):
        """
        Watch a stream from the API given a resource.
    
        :param resource: The plural resource you would like to watch.
        :return: A stream of json objs e.g. {"type": "MODIFED"|"ADDED"|"DELETED", "object":{...}}
        :rtype stream
        """
        # Append the resource version - this indicates where the 
        # watch should start.
        _log.info("Streaming API resources '%s' at version '%s'", path, resource_version)
        if resource_version:
            path += "?resourceVersion=%s" % resource_version

        session = requests.Session()
        if self.auth_token:
            _log.debug("Using Auth Token: %s", self.auth_token)
            session.headers.update({'Authorization': 'Bearer ' + self.auth_token})
        return session.get(path, verify=False, stream=True)
    
    def _get_api_resource(self, path):
        """
        Get a resource from the API specified API path.
        :return: A JSON API object
        :rtype json dict
        """
        _log.debug("Getting API Resource: %s", path)
        session = requests.Session()
        if self.auth_token:
            _log.debug("Using Auth Token: %s", self.auth_token)
            session.headers.update({'Authorization': 'Bearer ' + self.auth_token})
        response = session.get(path, verify=False)
        return json.loads(response.text)


if __name__ == '__main__':
    # Configure logging.
    log_file = "/var/log/calico/kubernetes/policy/agent.log"
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))
    formatter = logging.Formatter(LOG_FORMAT)
    file_hdlr = ConcurrentRotatingFileHandler(filename=log_file,
                                              maxBytes=1000000,
                                              backupCount=5)
    file_hdlr.setFormatter(formatter)
    _log.addHandler(file_hdlr)
    _log.setLevel(LOG_LEVEL)

    # Log to stderr as well.
    stdout_hdlr = logging.StreamHandler(sys.stderr)
    stdout_hdlr.setLevel(LOG_LEVEL)
    stdout_hdlr.setFormatter(formatter)
    _log.addHandler(stdout_hdlr)

    try:
        PolicyAgent().run()
    except Exception:
        # Log the exception
        _log.exception("Unhandled Exception killed agent")
        raise
