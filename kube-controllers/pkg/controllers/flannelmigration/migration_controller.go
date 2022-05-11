// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	namespaceKubeSystem        = "kube-system"
	migrationNodeSelectorKey   = "projectcalico.org/node-network-during-migration"
	migrationNodeInProgressKey = "projectcalico.org/node-flannel-migration-in-progress"
	addOnManagerLabelKey       = "addonmanager.kubernetes.io/mode"
	canalDaemonsetName         = "canal"
	calicoConfigMapName        = "calico-config"
	calicoConfigMapMtuKey      = "veth_mtu"
	migrationConfigMapName     = "flannel-migration-config"
	migrationConfigMapEnvKey   = "flannel_subnet_env"
	flannelConfigFile          = "run/flannel/subnet.env"
	flannelContainerName       = "kube-flannel"
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
	// nodeNetworkNone is a map value indicates there should be neither Flannel nor Calico running on the node.
	nodeNetworkNone = map[string]string{migrationNodeSelectorKey: "none"}
	// nodeMigrationInProgress is a map value indicates a node is running network migration.
	nodeMigrationInProgress = map[string]string{migrationNodeInProgressKey: "true"}
	// Possible Labels for Flannel daemonset pod.
	flannelPodLabel = map[string]string{"app": "flannel", "k8s-app": "flannel"}
	// Label for Canal daemonset pod.
	canalPodLabel = map[string]string{"k8s-app": "canal"}
	// Label for Calico daemonset pod.
	calicoPodLabel = map[string]string{"k8s-app": "calico-node"}
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

// Wait before start.
func (c *flannelMigrationController) waitBeforeStart() {
	if c.config.DebugWaitBeforeStart > 0 {
		time.Sleep(time.Duration(c.config.DebugWaitBeforeStart) * time.Second)
	}
}

// Wait before exit.
func (c *flannelMigrationController) waitBeforeExit() {
	if c.config.DebugWaitBeforeExit > 0 {
		time.Sleep(time.Duration(c.config.DebugWaitBeforeExit) * time.Second)
	}
}

// Handle error by simply exit 1. Allow controller to restart.
func (c *flannelMigrationController) HandleError(err error) {
	c.waitBeforeExit()
	log.Fatalf("Migration controller stopped.")
}

// Migration Completed. Stop controller.
func (c *flannelMigrationController) StopController(msg string) {
	log.Infof("%s", msg)
	c.waitBeforeExit()
	os.Exit(0)
}

// Run starts the migration controller. It does start-of-day preparation
// and then run entire migration process.
func (c *flannelMigrationController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	c.waitBeforeStart()
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

	// Disable VXLAN in Felix explicitly. We don't want to turn this on until we have
	// updated the Calico nodes with the necessary VTEP information from flannel. This ensures
	// that Calico will respect flannel's VXLAN traffic once enabled.
	if err := c.ipamMigrator.SetVXLANEnabled(context.TODO(), false); err != nil {
		log.WithError(err).Errorf("Error disabling VXLAN")
		c.HandleError(err)
	}

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

	// Now that we have populated Calico with flannel's VXLAN data, we can enable VXLAN in Felix.
	if err := c.ipamMigrator.SetVXLANEnabled(context.TODO(), true); err != nil {
		log.WithError(err).Errorf("Error enabling VXLAN")
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
		log.WithError(err).Infof("Error running ipam migration for new node %s. This node has not got Flannel yet. Just need restart to handle it.", node.Name)
		log.Fatal("Migration controller will restart and continue...")
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

// Get Flannel config from subnet.env file by kubectl exec into Flannel/Canal daemonset pod.
// Once a valid config has been read, migration controller need to update migration config map.
// This is because if we just rely on getting config from Flannel/Canal daemonset pod, there are
// chances that at the final stage of migration, all Flannel/Canal daemonset pod has been deleted
// but at the same time migration controller restart itself.
func (c *flannelMigrationController) readAndUpdateFlannelEnvConfig() error {
	// Work out the Flannel config by kubectl exec into daemonset pod on controller node.
	log.Infof("Trying to read Flannel env config by executing into daemonet pod.")
	var podLabel map[string]string
	if c.config.IsRunningCanal() {
		podLabel = canalPodLabel
	} else {
		podLabel = flannelPodLabel
	}

	n := k8snode(c.config.PodNodeName)
	data, err := n.execCommandInPod(c.k8sClientset, namespaceKubeSystem, flannelContainerName,
		podLabel, "cat", flannelConfigFile)
	if err != nil {
		return err
	}

	if err = c.config.ReadFlannelConfig(data); err != nil {
		return err
	}
	if err = c.config.ValidateFlannelConfig(); err != nil {
		return err
	}
	log.WithField("flannelConfig", c.config).Info("Flannel env config parsed successfully.")

	// Convert subnet.env content to json string and update flannel-migration-config ConfigMap.
	// So that it could be populated into migration controller pod next time it starts.
	val := strings.Replace(data, "\n", ";", -1)
	err = updateConfigMapValue(c.k8sClientset, namespaceKubeSystem, migrationConfigMapName, migrationConfigMapEnvKey, val)
	if err != nil {
		return err
	}
	log.Infof("Flannel subnet.env stored in migration config map: '%s'.", val)

	return nil
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

	// Check if addon manager label exists
	found, val, err := d.getLabelValue(c.k8sClientset, namespaceKubeSystem, addOnManagerLabelKey)
	if err != nil {
		return false, err
	}

	if found {
		log.Infof("Daemonset %s got addon manager label set to %s, abort migration process.",
			c.config.FlannelDaemonsetName, val)
		return false, nil
	}

	// Check if we need to read and update Flannel subnet.env config.
	if !c.config.subnetEnvPopulated() {
		err = c.readAndUpdateFlannelEnvConfig()
		if err != nil {
			return false, err
		}
	}

	// Update calico-config ConfigMap veth_mtu.
	// So that it could be populated into calico-node pods.
	err = updateConfigMapValue(c.k8sClientset, namespaceKubeSystem, calicoConfigMapName, calicoConfigMapMtuKey, fmt.Sprintf("%d", c.config.FlannelMTU))
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

	// A node can be in different migration status indicated by the value of labels
	// "projectcalico.org/node-network-during-migration" (abbr. network) and "projectcalico.org/node-flannel-migration-in-progress" (abbr. in-progress)
	// case 1. No label at all.
	//         This is the first time migration controller starts. The node is running Flannel.
	//         Or in rare cases, the node is a new node added between two separate migration processes. e.g. migration controller restarted.
	//         The controller will not try to distinguish these two scenarios. It regards the new node as if Flannel is running.
	//         This simplifies the main controller logic and increases robustness.
	// case 2. network == flannel with no in-progress label. The node has been identified by previous migration process that Flannel is running.
	// case 3. network == none and in-progress == true. The node has completed ipam migration. It started network migration process.
	// case 4. network == calico and in-progress == true. The node got flannel network removed but has not completed migration process.
	// case 5. network == calico with no in-progress label. The node is running Calico.
	//
	// The controller will start ipam and network migration for all cases except case 5.

	// Work out list of nodes not running Calico. It could happen that all nodes are running Calico and it returns an empty list.
	items := c.indexer.List()
	var controllerNodes []*v1.Node
	var masterNodes []*v1.Node
	for _, obj := range items {
		node := obj.(*v1.Node)

		migrationInProgress, _ := getNodeLabelValue(node, migrationNodeInProgressKey)
		network, _ := getNodeLabelValue(node, migrationNodeSelectorKey)

		if network != "calico" || migrationInProgress == "true" {
			if network != "calico" && network != "none" {
				// Allow Flannel to run if the node is not starting to run Calico or Flannel network has been removed.
				n := k8snode(node.Name)
				if err := n.addNodeLabels(c.k8sClientset, nodeNetworkFlannel); err != nil {
					log.WithError(err).Errorf("Error adding node label to node %s.", node.Name)
					return []*v1.Node{}, err
				}
			}

			addToList := true
			// check if migration controller is running on this node.
			// If it is, make sure it is the last node we try to process.
			// Note: we should only ever have a list with a single element. However, to be safe,
			// we use a list so that we don't accidentally skip any nodes if multiple trigger this branch.
			if node.Name == c.config.PodNodeName {
				log.Infof("Migration controller is running on node %s.", node.Name)
				controllerNodes = append(controllerNodes, node)
				addToList = false
			}

			// check if this node is master node.
			// If it is, make sure it is added at the end of the processing list.
			if nodeIsMaster(node) {
				log.Infof("Master node is %s.", node.Name)
				masterNodes = append(masterNodes, node)
				addToList = false
			}

			if addToList {
				nodes = append(nodes, node)
			}
		}
	}

	// Now we have a list of nodes which does not include control plane nodes, nor any node running this controller.
	// We need to sort the list so that we would have a deterministic ordering of nodes.
	// If controller failed and restarted, it will start to process the same node again.
	// This is to prevent migration controller to migrate another node without addressing previous failure.
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	// Migrate master nodes after worker nodes (except node running migration controller).
	// The advantage is we would have more confidence migration process works on worker nodes before running
	// it on master nodes.
	if len(masterNodes) != 0 {
		sort.SliceStable(masterNodes, func(i, j int) bool { return masterNodes[i].Name < masterNodes[j].Name })
		log.Infof("Adding control plane nodes to end of queue: %v", masterNodes)
		nodes = append(nodes, masterNodes...)
	}

	// Currently only a single controllerNode is used but leave it as a slice for now.
	if len(controllerNodes) != 0 {
		for _, cn := range controllerNodes {
			if !nodeInList(cn, masterNodes) {
				log.Infof("Adding node hosting migration controller to end of queue: %s", cn)
				nodes = append(nodes, cn)
			}
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

func nodeInList(node *v1.Node, nodes []*v1.Node) bool {
	for _, n := range nodes {
		if n.Name == node.Name {
			return true
		}
	}
	return false
}

func nodeIsMaster(node *v1.Node) bool {
	// node-role.kubernetes.io/controlplane: true is the label attached to rancher master nodes.
	for _, key := range []string{"node-role.kubernetes.io/master", "node-role.kubernetes.io/controlplane"} {
		_, err := getNodeLabelValue(node, key)
		if err == nil {
			return true
		}
	}

	return false
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
