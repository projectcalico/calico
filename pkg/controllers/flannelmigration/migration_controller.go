// Copyright (c) 2019 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flannelmigration

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	namespaceKubeSystem      = "kube-system"
	migrationNodeSelectorKey = "projectcalico.org/node-network-during-migration"
)

// Flannel migration controller consists of three major components.
// IPAM Migrator who setups Calico IPAM based on Flannel network configurations.
// Network Migrator who removes Flannel vxlan data plane and allow Calico vxlan network to be setup on nodes.
// Main controller logic controls the entire migration process and handle new node events.

var (
	// nodeNetworkFlannel is a map value indicates a node is still part of Flannel vxlan network.
	// This is used both as a nodeSelector for Flannel daemonset and a label for a node.
	nodeNetworkFlannel = map[string]string{migrationNodeSelectorKey: "flannel"}
	// nodeNetworkCalico is a map value indicates a node is becoming part of Calico vxlan network.
	// This is used both as a nodeSelector for Calico daemonset and a label for a node.
	nodeNetworkCalico = map[string]string{migrationNodeSelectorKey: "calico"}
	// nodeNetworkNone is a map value indicates a node is running network migration.
	nodeNetworkNone = map[string]string{migrationNodeSelectorKey: "none"}
)

// flannelMigrationController implements the Controller interface.
type flannelMigrationController struct {
	ctx          context.Context
	informer     cache.Controller
	indexer      cache.Indexer
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset

	// ipamMigrator runs ipam migration process.
	ipamMigrator ipamMigrator

	// networkMigrator runs network migration process.
	networkMigrator *networkMigrator

	// List of nodes need to be migrated.
	flannelNodes []*v1.Node

	// Configurations for migration controller.
	config *Config
}

// NewFlannelMigrationController Constructor for Flannel migration controller
func NewFlannelMigrationController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, cfg *Config) controller.Controller {
	mc := &flannelMigrationController{
		ctx:             ctx,
		calicoClient:    calicoClient,
		k8sClientset:    k8sClientset,
		ipamMigrator:    NewIPAMMigrator(ctx, k8sClientset, calicoClient, cfg),
		networkMigrator: NewNetworkMigrator(ctx, k8sClientset, calicoClient, cfg),
		config:          cfg,
	}

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Setup event handlers
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			mc.processNewNode(obj.(*v1.Node))
		},
	}

	// Informer handles managing the watch and signals us when nodes are added.
	mc.indexer, mc.informer = cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, handlers, cache.Indexers{})

	return mc
}

// Handle error by simply exit 1. Allow controller to restart.
func (c *flannelMigrationController) HandleError(err error) {
	log.Fatalf("Migration controller stopped.")
}

// Migration Completed. Stop controller.
func (c *flannelMigrationController) StopController(msg string) {
	log.Infof("%s", msg)
	os.Exit(0)
}

// Run starts the migration controller. It does start-of-day preparation
// and then run entire migration process. We ignore reconcilerPeriod and threadiness.
func (c *flannelMigrationController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting Migration controller")

	// Check the status of the cluster to see if we need to migrate.
	shouldMigrate, err := c.CheckShouldMigrate()
	if err != nil {
		log.WithError(err).Errorf("Error checking status, Stopping Migration controller.")
		c.HandleError(err)
	}
	if !shouldMigrate {
		c.StopController("No migration needed. Stopping migration controller.")
	}

	// Start migration process.

	// Initialise Calico IPAM before we handle any nodes.
	err = c.ipamMigrator.InitialiseIPPoolAndFelixConfig()
	if err != nil {
		log.WithError(err).Errorf("Error initialising default ipool and Felix configuration.")
		c.HandleError(err)
	}

	// Wait till k8s cache is synced
	go c.informer.Run(stopCh)
	log.Infof("Waiting to sync with Kubernetes API (Nodes)")
	for !c.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.Infof("Finished syncing with Kubernetes API (Nodes)")

	// Run IPAM migration. Get list of nodes need to be migrated.
	c.flannelNodes, err = c.runIpamMigrationForNodes()
	if err != nil {
		log.WithError(err).Errorf("Error running ipam migration.")
		c.HandleError(err)
	}

	// Add node selector "projectcalico.org/node-network-during-migration==flannel" to Flannel daemonset.
	// This would prevent Flannel pod running on any new nodes or a node which has been migrated to Calico network.
	d := daemonset(c.config.FlannelDaemonsetName)
	err = d.AddNodeSelector(c.k8sClientset, namespaceKubeSystem, nodeNetworkFlannel)
	if err != nil {
		log.WithError(err).Errorf("Error adding node selector to Flannel daemonset.")
		c.HandleError(err)
	}

	// Start network migration.
	err = c.runNetworkMigrationForNodes()
	if err != nil {
		log.WithError(err).Errorf("Error running network migration.")
		c.HandleError(err)
	}

	// Complete migration process.
	err = c.completeMigration()
	if err != nil {
		log.WithError(err).Errorf("Error completing migration.")
		c.HandleError(err)
	}

	c.StopController("All done. Stopping Migration controller")
}

// For new node, setup Calico IPAM based on node pod CIDR and update node selector.
// This makes sure a new node get Calico installed in the middle of migration process.
func (c *flannelMigrationController) processNewNode(node *v1.Node) {
	// Do not process any new node unless existing nodes been processed.
	for len(c.flannelNodes) == 0 {
		log.Debugf("New node %s skipped.", node.Name)
		return
	}

	// Defensively check node label again to make sure the node has not been processed by anyone.
	_, err := getNodeLabelValue(node, migrationNodeSelectorKey)
	if err == nil {
		// Node got label already. Skip it.
		log.Infof("New node %s has been processed.", node.Name)
		return
	}

	log.Infof("Start processing new node %s.", node.Name)
	err = c.ipamMigrator.SetupCalicoIPAMForNode(node)
	if err != nil {
		log.WithError(err).Fatalf("Error running ipam migration for new node %s.", node.Name)
		return
	}

	n := k8snode(node.Name)
	err = n.addNodeLabels(c.k8sClientset, nodeNetworkCalico)
	if err != nil {
		log.WithError(err).Fatalf("Error adding node label to enable Calico network for new node %s.", node.Name)
		return
	}

	log.Infof("Complete processing new node %s.", node.Name)
}

// Check if controller should start migration process.
func (c *flannelMigrationController) CheckShouldMigrate() (bool, error) {
	// Check if we are running Canal.
	d := daemonset(canalDaemonsetName)
	notFound, err := d.CheckNotExists(c.k8sClientset, namespaceKubeSystem)
	if err != nil {
		return false, err
	}

	if !notFound {
		log.Info("Canal daemonset exists, we are migrating from Canal to Calico.")
		c.config.FlannelDaemonsetName = canalDaemonsetName
	}

	// Check Flannel daemonset.
	d = daemonset(c.config.FlannelDaemonsetName)
	notFound, err = d.CheckNotExists(c.k8sClientset, namespaceKubeSystem)
	if err != nil {
		return false, err
	}

	if notFound {
		log.Infof("Daemonset %s not exists, no migration process is needed.", c.config.FlannelDaemonsetName)
		return false, nil
	}

	// Update calico-config ConfigMap veth_mtu.
	// So that it could be populated into calico-node pods.
	err = updateConfigMapValue(c.k8sClientset, namespaceKubeSystem, calicoConfigMapName, calicoConfigMapMtuKey, string(c.config.FlannelMTU))
	if err != nil {
		return false, err
	}

	// Initialise IPAM migrator.
	err = c.ipamMigrator.Initialise()
	if err != nil {
		log.Info("IPAM migrator initialisation failed.")
		return false, nil
	}

	// Initialise network migrator.
	err = c.networkMigrator.Initialise()
	if err != nil {
		log.Info("Network migrator initialisation failed.")
		return false, nil
	}

	return true, nil
}

// Start ipam migration.
// This is to make sure Calico IPAM has been setup for the entire cluster.
// Return a list of nodes which has been processed successfully and should move on to next stage.
// If there is any error, return empty list.
func (c *flannelMigrationController) runIpamMigrationForNodes() ([]*v1.Node, error) {
	nodes := []*v1.Node{}

	// A node can be in different migration status indicated by the value of label "projectcalico.org/node-network-during-migration".
	// case 1. No label at all.
	//         This is the first time migration controller starts. The node is running Flannel.
	//         Or in rare cases, the node is a new node added between two separate migration processes. e.g. migration controller restarted.
	//         The controller will not try to distinguish these two scenarios. It regards the new node as if Flannel is running.
	//         This simplifies the main controller logic and increases robustness.
	// case 2. flannel. The node has been identified by previous migration process that Flannel is running.
	// case 3. unknown. The node has completed ipam migration. However, network migration process has not been done.
	// case 4. calico. The node is running Calico.
	//
	// The controller will start ipam and network migration for all cases except case 4.

	// Work out list of nodes not running Calico. It could happen that all nodes are running Calico and it returns an empty list.
	items := c.indexer.List()
	var controllerNode *v1.Node
	var masterNode *v1.Node
	for _, obj := range items {
		node := obj.(*v1.Node)

		val, _ := getNodeLabelValue(node, migrationNodeSelectorKey)
		if val != "calico" {
			n := k8snode(node.Name)
			if err := n.addNodeLabels(c.k8sClientset, nodeNetworkFlannel); err != nil {
				log.WithError(err).Errorf("Error adding node label to node %s.", node.Name)
				return []*v1.Node{}, err
			}

			addToList := true
			// check if migration controller is running on this node.
			// If it is, make sure it is the last node we try to process.
			if node.Name == c.config.PodNodeName {
				log.Infof("Migration controller is running on node %s.", node.Name)
				controllerNode = node
				addToList = false
			}
			// check if this node is master node.
			// If it is, make sure it is the second last node we try to process.
			_, err := getNodeLabelValue(node, "node-role.kubernetes.io/master")
			if err == nil {
				log.Infof("Master node is %s.", node.Name)
				masterNode = node
				addToList = false
			}

			if addToList {
				nodes = append(nodes, node)
			}
		}
	}

	// Now we have a list of nodes which does not include master node and controllerNode.
	// We need to sort the list so that, if controller failed and restarted, it will start
	// to process the same node again. This is to prevent migration controller to migrate another
	// node without addressing previous failure.
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	if masterNode != nil {
		log.Infof("Master node %s is last node to be migrated.", masterNode.Name)
		nodes = append(nodes, masterNode)
	}

	if controllerNode != nil {
		log.Infof("Controller node %s is last node to be migrated.", controllerNode.Name)
		if controllerNode != masterNode {
			nodes = append(nodes, controllerNode)
		}
	}

	// At this point, any node would have a "projectcalico.org/node-network-during-migration" label.
	// The value is either "flannel" or "calico".
	// Start IPAM migration.
	err := c.ipamMigrator.MigrateNodes(nodes)
	if err != nil {
		log.WithError(err).Errorf("Error running ipam migration for nodes.")
		return nodes, err
	}

	return nodes, nil
}

// For each Flannel nodes, run network migration process.
func (c *flannelMigrationController) runNetworkMigrationForNodes() error {
	return c.networkMigrator.MigrateNodes(c.flannelNodes)
}

// Complete migration process.
func (c *flannelMigrationController) completeMigration() error {
	// Delete Flannel daemonset.
	d := daemonset(c.config.FlannelDaemonsetName)
	log.Infof("Start deleting %s daemonset.", c.config.FlannelDaemonsetName)
	err := d.DeleteForeground(c.k8sClientset, namespaceKubeSystem)
	if err != nil {
		log.WithError(err).Errorf("Failed to delete Flannel daemonset.")
		return err
	}

	log.Infof("Waiting for %s daemonset to disappear.", c.config.FlannelDaemonsetName)
	err = d.WaitForDaemonsetNotFound(c.k8sClientset, namespaceKubeSystem, 1*time.Second, 5*time.Minute)
	if err != nil {
		log.WithError(err).Errorf("Timeout deleting Flannel daemonset.")
		return err
	}

	// Remove nodeSelector for Calico Daemonet.
	d = daemonset(c.config.CalicoDaemonsetName)
	log.Infof("Remove node selector for daemonset %s.", c.config.CalicoDaemonsetName)
	err = d.RemoveNodeSelector(c.k8sClientset, namespaceKubeSystem, nodeNetworkCalico)
	if err != nil {
		log.WithError(err).Errorf("Failed to remove node selector for daemonset %s.", c.config.CalicoDaemonsetName)
		return err
	}

	// Remove node labels
	err = removeLabelForAllNodes(migrationNodeSelectorKey)
	if err != nil {
		log.WithError(err).Errorf("Failed to remove node label %s.", migrationNodeSelectorKey)
		return err
	}
	return nil
}
