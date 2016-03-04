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
ALPHA_API = "%s/apis/net.alpha.kubernetes.io/v1alpha1"
NET_POLICY_PATH = ALPHA_API + "/networkpolicys"
NET_POLICY_WATCH_PATH = ALPHA_API + "/watch/networkpolicys"

# Mapping of resource to api URL.
GET_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/pods",
            RESOURCE_TYPE_NAMESPACE: "%s/api/v1/namespaces",
            RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_PATH}
WATCH_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/watch/pods",
              RESOURCE_TYPE_NAMESPACE: "%s/api/v1/watch/namespaces",
              RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_WATCH_PATH}

# Annotation to look for network-isolation on namespaces.
NS_POLICY_ANNOTATION = "net.alpha.kubernetes.io/network-isolation"

# Tier name to use for policies.
NET_POL_TIER_NAME = "k8s-network-policy"

# Environment variables for getting the Kubernetes API.
K8S_SERVICE_PORT = "KUBERNETES_SERVICE_PORT"
K8S_SERVICE_HOST = "KUBERNETES_SERVICE_HOST"

# Label which represents the namespace a given pod belongs to.
K8S_NAMESPACE_LABEL = "calico/k8s_ns"

# Format to use for namespace profile names.
NS_PROFILE_FMT = "k8s_ns.%s"

# Format to use for labels inherited from a namespace.
NS_LABEL_KEY_FMT = "k8s_ns/label/%s"

# Max number of updates to queue.
# Assuming 10 pods per host, 1000 hosts, we may queue up to
# 10,000 updates at start of day.
MAX_QUEUE_SIZE = 10000

# Seconds to wait when adding to a full queue.
# It should easily not take more than a second to complete processing of
# an event off the queue.  Allow for five times that much to be safe.
QUEUE_PUT_TIMEOUT = 5

# Update types.
TYPE_ADDED = "ADDED"
TYPE_MODIFIED = "MODIFIED"
TYPE_DELETED = "DELETED"
TYPE_ERROR = "ERROR"
