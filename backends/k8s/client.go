package k8s

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kelseyhightower/confd/log"
	capi "github.com/projectcalico/libcalico-go/lib/api"
	backendapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	calicok8s "github.com/projectcalico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ipPool         = "/calico/v1/ipam/v4/pool"
	global         = "/calico/bgp/v1/global"
	globalASN      = "/calico/bgp/v1/global/as_num"
	globalNodeMesh = "/calico/bgp/v1/global/node_mesh"
	allNodes       = "/calico/bgp/v1/host"
	globalLogging  = "/calico/bgp/v1/global/loglevel"
)

var (
	singleNode = regexp.MustCompile("^/calico/bgp/v1/host/([a-zA-Z0-9._-]*)$")
	ipBlock    = regexp.MustCompile("^/calico/ipam/v2/host/([a-zA-Z0-9._-]*)/ipv4/block")
)

type Client struct {
	clientSet *kubernetes.Clientset

	// We use the calico K8s backend client to access the various Calico related config
	// with the exception of the node-specific config (BGP peers and BGP config) where we
	// use the Kubernetes API to query the nodes and use the Calico node clients to
	// convert to Calico KVPairs -- this results in fewer Node list queries.
	calicoK8sClient   *calicok8s.KubeClient
	nodeBgpPeerClient resources.K8sNodeResourceClient
	nodeBgpCfgClient  resources.K8sNodeResourceClient
}

func NewK8sClient(kubeconfig string) (*Client, error) {

	log.Debug("Building k8s client")

	// Set an explicit path to the kubeconfig if one
	// was provided.
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	if kubeconfig != "" {
		log.Debug(fmt.Sprintf("Using kubeconfig: \n%s", kubeconfig))
		loadingRules.ExplicitPath = kubeconfig
	}

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Create the clientset (we use this for Node queries).
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	log.Debug(fmt.Sprintf("Created k8s clientSet: %+v", cs))

	// Create the Calico backend client.  We use this to access all of the
	// custom resources.
	calicoK8sClient, err := calicok8s.NewKubeClient(&capi.KubeConfig{
		Kubeconfig: kubeconfig,
	})

	if err != nil {
		return nil, err
	}

	kubeClient := &Client{
		clientSet:         cs,
		calicoK8sClient:   calicoK8sClient,
		nodeBgpPeerClient: resources.NewNodeBGPPeerClient(cs),
		nodeBgpCfgClient:  resources.NewNodeBGPConfigClient(cs),
	}

	return kubeClient, nil
}

// GetValues takes the etcd like keys and route it to the appropriate k8s API endpoint.
func (c *Client) GetValues(keys []string) (map[string]string, error) {
	var vars = make(map[string]string)
	for _, key := range keys {
		log.Debug(fmt.Sprintf("Getting key %s", key))
		if m := singleNode.FindStringSubmatch(key); m != nil {
			host := m[len(m)-1]
			kNode, err := c.clientSet.Nodes().Get(host, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			err = c.populateNodeDetails(kNode, vars)
			if err != nil {
				return nil, err
			}
			// Find the podCIDR assigned to individual Nodes
		} else if m := ipBlock.FindStringSubmatch(key); m != nil {
			host := m[len(m)-1]
			kNode, err := c.clientSet.Nodes().Get(host, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			cidr := kNode.Spec.PodCIDR
			parts := strings.Split(cidr, "/")
			cidr = strings.Join(parts, "-")
			vars[key+"/"+cidr] = "{}"
		}

		switch key {
		case global:
			// Set default values for fields that we always expect to have.
			vars[globalLogging] = "info"
			vars[globalASN] = "64512"
			vars[globalNodeMesh] = `{"enabled": true}`

			// Global data consists of both global config and global peers.
			kvps, err := c.calicoK8sClient.List(model.GlobalBGPConfigListOptions{})
			if err != nil {
				return nil, err
			}
			c.populateFromKVPairs(kvps, vars)

			kvps, err = c.calicoK8sClient.List(model.GlobalBGPPeerListOptions{})
			if err != nil {
				return nil, err
			}
			c.populateFromKVPairs(kvps, vars)
		case globalNodeMesh:
			// This is needed as there are calls to 'global' and directly to 'global/node_mesh'
			// Default to true, but we may override this if a value is configured.
			vars[globalNodeMesh] = `{"enabled": true}`

			// Get the configured value.
			kvps, err := c.calicoK8sClient.List(model.GlobalBGPConfigListOptions{Name: "NodeMeshEnabled"})
			if err != nil {
				return nil, err
			}
			c.populateFromKVPairs(kvps, vars)
		case ipPool:
			kvps, err := c.calicoK8sClient.List(model.IPPoolListOptions{})
			if err != nil {
				return nil, err
			}
			c.populateFromKVPairs(kvps, vars)
		case allNodes:
			nodes, err := c.clientSet.Nodes().List(metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			for _, kNode := range nodes.Items {
				err := c.populateNodeDetails(&kNode, vars)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	log.Debug(fmt.Sprintf("%v", vars))
	return vars, nil
}

// WatchPrefix is not implemented - K8s backend only supports interval watches.
func (c *Client) WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) (uint64, error) {
	<-stopChan
	return 0, nil
}

// populateNodeDetails populates the given kvps map with values we track from the k8s Node object.
func (c *Client) populateNodeDetails(kNode *kapiv1.Node, vars map[string]string) error {
	kvps := []*model.KVPair{}

	// Start with the main Node configuration
	cNode, err := resources.K8sNodeToCalico(kNode)
	if err != nil {
		log.Error("Failed to parse k8s Node into Calico Node")
		return err
	}
	kvps = append(kvps, cNode)

	// Add per-node BGP config (each of the per-node resource clients also implements
	// the CustomK8sNodeResourceList interface, used to extract per-node resources from
	// the Node resource.
	if cfg, err := c.nodeBgpCfgClient.ExtractResourcesFromNode(kNode); err != nil {
		log.Error("Failed to parse BGP configs from node resource - skip config data")
	} else {
		kvps = append(kvps, cfg...)
	}

	if peers, err := c.nodeBgpPeerClient.ExtractResourcesFromNode(kNode); err != nil {
		log.Error("Failed to parse BGP peers from node resource - skip config data")
	} else {
		kvps = append(kvps, peers...)
	}

	// Populate the vars map from the KVPairs.
	c.populateFromKVPairs(kvps, vars)

	return nil
}

// populateFromKVPairs populates the vars KV map from the supplied set of
// KVPairs.  This uses the libcalico-go compat module and serialization functions
// to write out the KVPairs in etcdv2 format.  This works in conjunction with the
// etcdVarClient defined below which provides a "mock" etcd backend which actually
// just writes out data to the vars map.
func (c *Client) populateFromKVPairs(kvps []*model.KVPair, vars map[string]string) {
	// Create a etcdVarClient to write the KVP results in the vars map, using the
	// compat adaptor to write the values in etcdv2 format.
	client := compat.NewAdaptor(&etcdVarClient{vars: vars})
	for _, kvp := range kvps {
		client.Apply(kvp)
	}
}

// etcdVarClient implements the libcalico-go backend api.Client interface.  It is used to
// write the KVPairs retrieved from the Kubernetes datastore driver into the KV map
// using etcdv2 naming scheme.
type etcdVarClient struct {
	vars map[string]string
}

func (c *etcdVarClient) Create(kvp *model.KVPair) (*model.KVPair, error) {
	log.Fatal("Create should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Update(kvp *model.KVPair) (*model.KVPair, error) {
	log.Fatal("Update should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	path, err := model.KeyToDefaultPath(kvp.Key)
	if err != nil {
		log.Error("Unable to create path from Key: %s", kvp.Key)
		return nil, err
	}
	value, err := model.SerializeValue(kvp)
	if err != nil {
		log.Error("Unable to serialize value: %s", kvp.Key)
		return nil, err
	}
	c.vars[path] = string(value)
	return kvp, nil
}

func (c *etcdVarClient) Delete(kvp *model.KVPair) error {
	// Delete may be invoked as part of the multi-key resources, but since we start
	// from an empty map each time, we never need to delete entries.
	log.Debug("Delete ignored")
	return nil
}

func (c *etcdVarClient) Get(key model.Key) (*model.KVPair, error) {
	log.Fatal("Get should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) List(list model.ListInterface) ([]*model.KVPair, error) {
	log.Fatal("List should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Syncer(callbacks backendapi.SyncerCallbacks) backendapi.Syncer {
	log.Fatal("Syncer should not be invoked")
	return nil
}

func (c *etcdVarClient) EnsureInitialized() error {
	log.Fatal("EnsureIntialized should not be invoked")
	return nil
}

func (c *etcdVarClient) EnsureCalicoNodeInitialized(node string) error {
	log.Fatal("EnsureCalicoNodeInitialized should not be invoked")
	return nil
}
