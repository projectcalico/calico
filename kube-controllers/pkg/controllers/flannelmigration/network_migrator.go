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
	"fmt"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	calicoNodeContainerName     = "calico-node"
	calicoCniContainerName      = "install-cni"
	calicoCniConfigEnvName      = "CNI_CONF_NAME"
	calicoVxlanTunnelDeviceName = "vxlan.calico"

	// Sync period between kubelet and CNI config file change.
	// see https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/dockershim/network/cni/cni.go#L48
	defaultSyncConfigPeriod = time.Second * 5

	// For testing
	flannelMigrationPauseSecondsKey = "projectcalico.org/flannel-migration-pause-seconds"
)

// networkMigrator responsible for migrating Flannel vxlan data plane to Calico vxlan data plane.
type networkMigrator struct {
	ctx          context.Context
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset
	config       *Config

	// Calico node image used by network migrator.
	calicoImage string

	// Calico CNI config file name
	calicoCNIConfigName string
}

func NewNetworkMigrator(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, config *Config) *networkMigrator {
	return &networkMigrator{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		config:       config,
	}
}

// Initialise network migrator.
func (m *networkMigrator) Initialise() error {
	// Set calico image
	d := daemonset(m.config.CalicoDaemonsetName)
	image, err := d.GetContainerImage(m.k8sClientset, namespaceKubeSystem, calicoNodeContainerName)
	if err != nil {
		return err
	}
	m.calicoImage = image

	// Set calico CNI config file name
	cniConf, err := d.GetContainerEnv(m.k8sClientset, namespaceKubeSystem, calicoCniContainerName, calicoCniConfigEnvName)
	if err != nil {
		return err
	}
	m.calicoCNIConfigName = cniConf

	log.Infof("Network migrator initialised, container image %s, CNI config %s/%s.", m.calicoImage, m.config.CniConfigDir, m.calicoCNIConfigName)
	return nil
}

// Remove Flannel network device/routes on node.
// Write a dummy calico cni config file in front of Flannel/Canal CNI config.
// This will prevent Flannel CNI from running and make sure new pod created will not get networked
// until Calico CNI been correctly installed.
func (m *networkMigrator) removeFlannelNetworkAndInstallDummyCalicoCNI(node *v1.Node) error {
	// Deleting a tunnel device will remove routes, ARP and FDB entries related with the device.
	// Deleting cni0 device to remove routes to local pods.
	// It is possible tunnel device or cni0 has been deleted already.
	dummyCNI := `{ "name": "dummy", "plugins": [{ "type": "flannel-migration-in-progress" }]}`

	var cmd string
	if m.config.IsRunningCanal() {
		// Canal creates tunnel device but with no bridge. It uses Calico CNI.
		cmd = fmt.Sprintf("ip link show flannel.%d || exit 0 && { echo '%s' > /host/%s/%s ; ip link delete flannel.%d; } && exit 0 || exit 1",
			m.config.FlannelVNI, dummyCNI, m.config.CniConfigDir, m.calicoCNIConfigName, m.config.FlannelVNI)
	} else {
		// Flannel creates cni0 bridge and tunnel device. It delegates to bridge CNI.
		cmd = fmt.Sprintf("{ ip link show cni0; ip link show flannel.%d; } || exit 0 && { echo '%s' > /host/%s/%s ; ip link delete cni0 type bridge; ip link delete flannel.%d; } && exit 0 || exit 1",
			m.config.FlannelVNI, dummyCNI, m.config.CniConfigDir, m.calicoCNIConfigName, m.config.FlannelVNI)
	}

	// Run a remove-flannel pod with specified nodeName, this will bypass kube-scheduler.
	// https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#nodename
	pod := k8spod("remove-flannel")
	podLog, err := pod.RunPodOnNodeTillComplete(m.k8sClientset, namespaceKubeSystem, m.calicoImage, node.Name, cmd, m.config.CniConfigDir, true, true)
	if podLog != "" {
		log.Infof("remove-flannel pod logs: %s.", podLog)
	}

	// Wait twice as long as default sync period so kubelet has picked up dummy CNI config.
	// We probably need something better here but currently no API available for us to know
	// if kubelet sees new config.
	time.Sleep(2 * defaultSyncConfigPeriod)
	return err
}

// Check if node has got Calico vxlan network.
func (m *networkMigrator) checkCalicoVxlan(node *v1.Node) error {
	// Check if Calico tunnel device exists for 10 seconds.
	cmd := fmt.Sprintf("for i in $(seq 1 10); do ip link show %s && code=0 && break || code=$? && sleep 1; done; (exit $code)", calicoVxlanTunnelDeviceName)

	pod := k8spod("check-calico")
	podLog, err := pod.RunPodOnNodeTillComplete(m.k8sClientset, namespaceKubeSystem, m.calicoImage, node.Name, cmd, m.config.CniConfigDir, true, true)
	if podLog != "" {
		log.Infof("check-calico pod logs: %s.", podLog)
	}

	return err
}

// Drain node, remove Flannel and setup Calico network for a node.
func (m *networkMigrator) setupCalicoNetworkForNode(node *v1.Node) error {
	log.Infof("Setting node label to disable Flannel daemonset pod on node %s.", node.Name)

	// Label nodeMigrationInProgress marks that the node is in migration process.
	n := k8snode(node.Name)
	err := n.addNodeLabels(m.k8sClientset, nodeMigrationInProgress)
	if err != nil {
		log.WithError(err).Errorf("Error adding node labels to disable Flannel network and mark migration in process for node %s.", node.Name)
		return err
	}

	// Cordon and Drain node. Make sure no pod (except daemonset pod or pod with nodeName selector) can run on this node.
	err = n.Drain()
	if err != nil {
		log.WithError(err).Errorf("failed to drain node %s", node.Name)
		return err
	}

	// Label the node to evict the flannel / canal pod from this node. Do this after evicting other pods.
	err = n.addNodeLabels(m.k8sClientset, nodeNetworkNone)
	if err != nil {
		log.WithError(err).Errorf("Error adding node labels to disable Flannel network and mark migration in process for node %s.", node.Name)
		return err
	}

	log.Infof("Removing flannel tunnel device/routes on %s.", node.Name)
	// Remove Flannel network from node.
	// Note Flannel vxlan tunnel device (flannel.1) is created by Flannel daemonset pod (not Flannel CNI)
	// Therefor if Flannel daemonset pod can not run on this node, the tunnel device will not be recreated
	// after we delete it.
	err = m.removeFlannelNetworkAndInstallDummyCalicoCNI(node)
	if err != nil {
		log.WithError(err).Errorf("failed to remove flannel network on node %s", node.Name)
		return err
	}

	log.Infof("Deleting non-host-networked pods on %s.", node.Name)
	// Delete all pods on the node which is not host networked.
	err = n.deletePodsForNode(m.k8sClientset, func(pod *v1.Pod) bool {
		return !pod.Spec.HostNetwork
	})
	if err != nil {
		log.WithError(err).Errorf("failed to delete non-host-networked pods on node %s", node.Name)
		return err
	}

	// Set node label so that Calico daemonset pod start to run on this node.
	// This will install Calico CNI configuration file.
	// It will take the preference over Flannel CNI config or Canal CNI config.
	log.Infof("Setting node label to enable Calico daemonset pod on %s.", node.Name)
	err = n.addNodeLabels(m.k8sClientset, nodeNetworkCalico)
	if err != nil {
		log.WithError(err).Errorf("Error adding node label to enable Calico network for node %s.", node.Name)
		return err
	}

	log.Infof("Wait up to 5 minutes for Calico daemonset pod to become Ready on %s.", node.Name)
	// Calico daemonset pod should start running now.
	err = n.waitPodReadyForNode(m.k8sClientset, namespaceKubeSystem, 1*time.Second, 5*time.Minute, calicoPodLabel)
	if err != nil {
		log.WithError(err).Errorf("Calico node pod failed on node %s", node.Name)
		return err
	}
	log.Infof("Calico daemonset pod is Ready on %s.", node.Name)

	// Calico network should have been setup.
	err = m.checkCalicoVxlan(node)
	if err != nil {
		log.WithError(err).Errorf("failed to check calico vxlan network on node %s", node.Name)
		return err
	}

	// Uncordon node.
	err = n.Uncordon()
	if err != nil {
		log.WithError(err).Errorf("failed to uncordon node %s", node.Name)
		return err
	}

	// Remove nodeMigrationInProgress label so that if migration controller restarts,
	// it will not try to to migrate this node again.
	err = n.removeNodeLabels(m.k8sClientset, nodeMigrationInProgress)
	if err != nil {
		log.WithError(err).Errorf("failed to remove node migration in process label for node %s", node.Name)
		return err
	}

	log.Infof("Calico networking is running on %s.", node.Name)
	return nil
}

// MigrateNodes setup Calico network for array of nodes.
func (m *networkMigrator) MigrateNodes(nodes []*v1.Node) error {
	log.Infof("Start network migration process for %d nodes.", len(nodes))
	for i, node := range nodes {
		// This is for testing purpose.
		// Pause until user remove a pause-seconds label.
		// This label has to be added to node before running migration controller.
		val, err := getNodeLabelValue(node, flannelMigrationPauseSecondsKey)
		if err == nil {
			// Label exists.
			if seconds, err := strconv.Atoi(val); err == nil && seconds > 0 {
				// Timeout is a valid number
				n := k8snode(node.Name)
				err = n.waitForNodeLabelDisappear(m.k8sClientset, flannelMigrationPauseSecondsKey, 1*time.Second, time.Duration(seconds)*time.Second)
				if err != nil {
					log.WithError(err).Warnf("Error waiting for pause migration label.")
				}
			}
		}

		log.Infof("Start setting up Calico network for node %s[index %d].", node.Name, i)
		err = m.setupCalicoNetworkForNode(node)
		if err != nil {
			// Error migrating a node. However, if the node has been removed before migration controller started,
			// just log and continue on to next node.
			n := k8snode(node.Name)
			notFound, checkErr := n.CheckNotExists(m.k8sClientset)
			if checkErr != nil {
				log.WithError(checkErr).Errorf("Check existence of %s failed.", node.Name)
			} else if notFound {
				log.Infof("Node %s has been removed, continue on to next node...", node.Name)
				continue
			}
			return err
		}
	}
	log.Infof("%d nodes completed network migration process.", len(nodes))

	return nil
}
