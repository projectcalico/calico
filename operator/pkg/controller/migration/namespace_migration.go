// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/tigera/operator/pkg/common"
)

// This package provides the utilities to migrate from a Calico manifest installation
// to an operator deployment.

const (
	// Label key set on nodes to indicate their migration status.
	nodeSelectorKey = "projectcalico.org/operator-node-migration"

	// Value used for the node selector for 'unmigrated' nodes
	nodeSelectorValuePre = "pre-operator"

	// Value used for the node selector for migrated nodes
	nodeSelectorValuePost = "migrated"

	// Kube system namespace name
	kubeSystem = "kube-system"

	typhaDeploymentName          = "calico-typha"
	nodeDaemonSetName            = "calico-node"
	kubeControllerDeploymentName = "calico-kube-controllers"
	calicoNodeMigrationName      = "calico-node-migration"

	k8sServicesEndpointConfigMap = "kubernetes-services-endpoint"

	defaultMaxUnavailable int32 = 1
)

var migratedNodeLabel = map[string]string{nodeSelectorKey: nodeSelectorValuePost}

type NamespaceMigration interface {
	NeedsCoreNamespaceMigration(ctx context.Context) (bool, error)
	Run(ctx context.Context, log logr.Logger) error
	NeedCleanup() bool
	CleanupMigration(ctx context.Context, log logr.Logger) error
}

type CoreNamespaceMigration struct {
	client            kubernetes.Interface
	informer          cache.Controller
	indexer           cache.Store
	stopCh            chan struct{}
	migrationComplete bool
}

// NeedsCoreNamespaceMigration returns true if any components still exist in
// the kube-system namespace.
// It checks the following in the kube-system namespace:
// calico-kube-controllers deployment, typha deployment, or calico-node deployment
func (m *CoreNamespaceMigration) NeedsCoreNamespaceMigration(ctx context.Context) (bool, error) {
	if m.migrationComplete {
		return false, nil
	}

	nds, err := m.client.AppsV1().DaemonSets(kubeSystem).Get(ctx, nodeDaemonSetName, metav1.GetOptions{})
	if err == nil && nds != nil && nds.DeletionTimestamp == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("failed to get daemonset %s in kube-system: %s", nodeDaemonSetName, err)
	}

	kcdeploy, err := m.client.AppsV1().Deployments(kubeSystem).Get(ctx, kubeControllerDeploymentName, metav1.GetOptions{})
	if err == nil && kcdeploy != nil && kcdeploy.DeletionTimestamp == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("failed to get deployment %s in kube-system: %s", kubeControllerDeploymentName, err)
	}

	tdeploy, err := m.client.AppsV1().Deployments(kubeSystem).Get(ctx, typhaDeploymentName, metav1.GetOptions{})
	if err == nil && tdeploy != nil && tdeploy.DeletionTimestamp == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("failed to get deployment %s in kube-system: %s", typhaDeploymentName, err)
	}

	return false, nil
}

// NewCoreNamespaceMigration initializes a CoreNamespaceMigration and returns a handle to it.
func NewCoreNamespaceMigration(clientset *kubernetes.Clientset) (NamespaceMigration, error) {
	migration := &CoreNamespaceMigration{migrationComplete: false, client: clientset}

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(migration.client.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Setup event handlers
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {},
	}

	// Informer handles managing the watch and signals us when nodes are added.
	migration.indexer, migration.informer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatcher,
		ObjectType:    &v1.Node{},
		ResyncPeriod:  0,
		Handler:       handlers,
		Indexers:      cache.Indexers{},
	})

	migration.stopCh = make(chan struct{})

	go migration.informer.Run(migration.stopCh)

	for !migration.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}

	return migration, nil
}

// LimitDaemonSetToMigratedNodes updates the ds DaemonSet passed in with a
// nodeSelector that will only allow pods to be schedueled on nodes with
// the key:value projectcalico.org/operator-node-migration:migrated.
// This is to ensure that only one kube-system calico-node or the new calico-node
// pod will attempt to run on one node at a time.
func LimitDaemonSetToMigratedNodes(ds *appsv1.DaemonSet) {
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	for k, v := range migratedNodeLabel {
		ds.Spec.Template.Spec.NodeSelector[k] = v
	}
}

// AddBindingForKubeSystemNode updates the ClusterRoleBinding passed in
// to also bind the service account in the kube-system namespace to the
// Role. Without this, when the new ClusterRoleBinding overwrites the
// previous role binding the kube-system calico-node account would lose
// permissions for accessing the datastore.
func AddBindingForKubeSystemNode(crb *rbacv1.ClusterRoleBinding) {
	// The node role and binding are the same name for the manifest installation and
	// operator install, so when it is updated also include a binding
	// to the calico-node SA in kube-system.
	if crb.Subjects == nil {
		crb.Subjects = []rbacv1.Subject{}
	}
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "calico-node",
		Namespace: kubeSystem,
	}, rbacv1.Subject{
		// Include system:nodes binding for RKE clusters with managed Calico CNI (Calico installed by RKE)
		// If we add detection of RKE as a provider then we should make this dependent on that.
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "Group",
		Name:     "system:nodes",
	})
}

// AddBindingForKubeSystemCNIPlugin updates the ClusterRoleBinding passed in
// to also bind the calico-cni-plugin service account in the kube-system namespace.
// During migration, nodes that haven't been migrated yet still run the CNI plugin
// as kube-system:calico-cni-plugin. Without this binding, pod creation fails on
// those nodes because the CNI plugin loses permissions to access Calico CRDs.
func AddBindingForKubeSystemCNIPlugin(crb *rbacv1.ClusterRoleBinding) {
	if crb.Subjects == nil {
		crb.Subjects = []rbacv1.Subject{}
	}
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "calico-cni-plugin",
		Namespace: kubeSystem,
	})
}

// We create a cluster role and cluster role binding to give the kube-system calico-node
// permissions to create serviceaccount tokens. This is needed to make sure that the down-level calico-node maintains
// the permissions it needs in order to launch, since the calico-node clusterrole is shared with the
// operator resource and the operator removes this permission on upgrade (instead
// delegating this power to the cni-plugin in the calico-system namespace).
//
// This logic can likely be removed after Calico v3.35, as we'll no longer need to support upgrading from versions
// where calico-node needed this permission.
func ClusterRoleBindingForKubeSystemNode() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: calicoNodeMigrationName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     calicoNodeMigrationName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: kubeSystem,
			},
		},
	}
	return crb
}

func ClusterRoleForKubeSystemNode() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: calicoNodeMigrationName,
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts/token"},
				ResourceNames: []string{"calico-node"},
				Verbs:         []string{"create"},
			},
		},
	}
	return role
}

// SetTyphaAntiAffinity updates the Deployment passed in with a PodAntiAffinity
// to ensure the new typha pods will not be scheduled to the same nodes as the
// 'old' typha pods.
func SetTyphaAntiAffinity(d *appsv1.Deployment) {
	if d.Spec.Template.Spec.Affinity == nil {
		d.Spec.Template.Spec.Affinity = &v1.Affinity{}
	}
	if d.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
		d.Spec.Template.Spec.Affinity.PodAntiAffinity = &v1.PodAntiAffinity{}
	}
	d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = []v1.PodAffinityTerm{
		{
			Namespaces: []string{kubeSystem},
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": typhaDeploymentName,
				},
			},
			TopologyKey: "kubernetes.io/hostname",
		},
	}
}

// Run will update old deployments and daemonsets, label nodes, migrate the
// calio-node pods on each node from the old pod to the new one, then clean up.
// The expectation is that this function will do the majority of the migration before
// returning (the exception being label clean up on the nodes), if there is an error
// it will be returned and the
func (m *CoreNamespaceMigration) Run(ctx context.Context, log logr.Logger) error {
	if err := m.deleteKubeSystemKubeControllers(ctx); err != nil {
		return fmt.Errorf("failed deleting kube-system calico-kube-controllers: %s", err.Error())
	}
	log.V(1).Info("Deleted previous calico-kube-controllers deployment")
	if err := m.labelUnmigratedNodes(ctx); err != nil {
		return fmt.Errorf("failed to label unmigrated nodes: %s", err.Error())
	}
	log.V(1).Info("All unmigrated nodes labeled")
	if err := m.ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady(ctx, log); err != nil {
		return fmt.Errorf("the kube-system node DaemonSet is not ready with the updated nodeSelector: %s", err.Error())
	}
	log.V(1).Info("Node selector added to kube-system node DaemonSet")
	if err := m.ensureTyphaRoom(ctx, log); err != nil {
		return fmt.Errorf("unable to ensure room for enough typhas: %s", err.Error())
	}
	log.V(1).Info("Ensured room for Typha deployments")
	if err := m.waitForOperatorTyphaDeploymentReady(ctx, log); err != nil {
		return fmt.Errorf("failed to wait for operator typha deployment to be ready: %s", err.Error())
	}
	log.V(1).Info("calico-system/calico-typha is running with expected replica count")
	if err := m.migrateEachNode(ctx, log); err != nil {
		return fmt.Errorf("failed to migrate all nodes: %s", err.Error())
	}
	log.V(1).Info("Nodes migrated")
	err := m.waitForOperatorCalicoNodeDaemonsetReady(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to wait for calico-node daemonset to be ready: %s", err.Error())
	}
	log.V(1).Info("calico-system/calico-node daemonset has been rolled out successfully")
	if err := m.deleteKubeSystemCalicoNode(ctx); err != nil {
		return fmt.Errorf("failed to delete kube-system node DaemonSet: %s", err.Error())
	}
	log.V(1).Info("kube-system node DaemonSet deleted")
	if err := m.deleteKubeSystemTypha(ctx); err != nil {
		return fmt.Errorf("failed to delete kube-system typha Deployment: %s", err.Error())
	}
	log.V(1).Info("kube-system typha deployment deleted")
	if err := m.deleteKubeSystemServiceEndPointConfigMap(ctx, log); err != nil {
		return fmt.Errorf("failed to delete kube-system k8sServicesEndpoint ConfigMap: %s", err.Error())
	}
	log.Info("Namespace migration complete")

	return nil
}

// ensureTyphaRoom analyzes the cluster and scales down the existing kube-system Typha deployment if needed
// in order to make room for the new operator-managed Typha deployment in the calico-system namespace.
func (m *CoreNamespaceMigration) ensureTyphaRoom(ctx context.Context, log logr.Logger) error {
	// Remove the typha autoscaler if one exists.
	if err := m.removeTyphaAutoscaler(ctx, log); err != nil {
		return err
	}

	// Get typha, if it exists.
	typha, err := m.client.AppsV1().Deployments(kubeSystem).Get(ctx, typhaDeploymentName, metav1.GetOptions{})
	if err != nil {
		if !apierrs.IsNotFound(err) {
			return err
		}
	}
	if typha == nil {
		// No Typha running - we're good to go.
		return nil
	}
	if typha.Spec.Replicas == nil {
		// No replicas - nothing to do.
		return nil
	}
	curReplicas := *typha.Spec.Replicas

	// Number of nodes in the cluster.
	nodeCount := 0
	for range m.indexer.List() {
		nodeCount++
	}

	// Total number of typhas we expect this cluster to need.
	expectedTyphas := common.GetExpectedTyphaScale(nodeCount)

	// We might need to scale down the currently running Typha.
	var desiredReplicas int32
	if nodeCount <= 1 {
		// If this is a single node cluster, just scale down Typha to 0 in order to
		// make room for the new Typha pod.
		desiredReplicas = 0
	} else if nodeCount <= 3 {
		// 2 or 3 node cluster, just keep a single Typha around during the update.
		desiredReplicas = 1
	} else {
		// More than 3 nodes. Make sure we have enough space for both to run.
		// Pick the smaller value of either the current count, or the total number of nodes
		// minus the number the operator will deploy.
		maxAvailableNodes := nodeCount - expectedTyphas
		if maxAvailableNodes < 0 {
			maxAvailableNodes = 1
		}
		desiredReplicas = min(int32(maxAvailableNodes), curReplicas)
	}
	if desiredReplicas != curReplicas {
		log.Info(fmt.Sprintf("Scaling kube-system/calico-typha deployment to %d replicas to make room for migration", desiredReplicas))
		typha.Spec.Replicas = &desiredReplicas
		_, err = m.client.AppsV1().Deployments(kubeSystem).Update(ctx, typha, metav1.UpdateOptions{})
		return err
	}
	return nil
}

// removeTyphaAutoscaler removes any typha autoscaler for the kube-system/calico-typha deployment so that the
// migration controller can manage the scale of that deployment.
func (m *CoreNamespaceMigration) removeTyphaAutoscaler(ctx context.Context, log logr.Logger) error {
	err := m.client.AppsV1().Deployments(kubeSystem).Delete(ctx, "calico-typha-horizontal-autoscaler", metav1.DeleteOptions{})
	if !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

// NeedCleanup returns true if any nodes still have migration labels that need to be removed.
// We check the node informer cache to avoid triggering unnecessary cleanup (including waiting
// for calico-node readiness) on clusters where no migration has occurred.
func (m *CoreNamespaceMigration) NeedCleanup() bool {
	if m.migrationComplete {
		return false
	}
	for _, obj := range m.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			continue
		}
		if _, exists := node.Labels[nodeSelectorKey]; exists {
			return true
		}
	}
	return false
}

// CleanupMigration ensures all labels used during the migration are removed
// and any migration resources are stopped.
func (m *CoreNamespaceMigration) CleanupMigration(ctx context.Context, log logr.Logger) error {
	if m.migrationComplete {
		return nil
	}
	// wait for calico-node rollout to avoid mass restart of calico-node pods
	err := m.waitForOperatorCalicoNodeDaemonsetReady(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to wait for calico-node daemonset to be ready: %s", err.Error())
	}
	if err := m.removeNodeMigrationLabelFromNodes(ctx); err != nil {
		return fmt.Errorf("error cleaning up node labels: %s", err)
	}

	close(m.stopCh)

	m.migrationComplete = true
	return nil
}

// deleteKubeSystemServiceEndPointConfigMap deletes the kubernetes-services-endpoint configmap
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemServiceEndPointConfigMap(ctx context.Context, log logr.Logger) error {
	err := m.client.CoreV1().ConfigMaps(kubeSystem).Delete(ctx, k8sServicesEndpointConfigMap, metav1.DeleteOptions{})
	if err != nil {
		if !apierrs.IsNotFound(err) {
			return err
		}
	} else {
		log.V(1).Info("kube-system services endpoint configmap deleted")
	}
	return nil
}

// deleteKubeSystemKubeControllers deletes the calico-kube-controllers deployment
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemKubeControllers(ctx context.Context) error {
	err := m.client.AppsV1().Deployments(kubeSystem).Delete(ctx, kubeControllerDeploymentName, metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// deleteKubeSystemTypha deletes the typha deployment
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemTypha(ctx context.Context) error {
	err := m.client.AppsV1().Deployments(kubeSystem).Delete(ctx, typhaDeploymentName, metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// deleteKubeSystemCalicoNode deletes the calico-node daemonset
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemCalicoNode(ctx context.Context) error {
	err := m.client.AppsV1().DaemonSets(kubeSystem).Delete(ctx, nodeDaemonSetName, metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// waitForOperatorTyphaDeploymentReady waits until the 'new' typha deployment in
// the calico-system namespace is ready before continuing, it will wait up to
// 10 minutes before returning with an error.
func (m *CoreNamespaceMigration) waitForOperatorTyphaDeploymentReady(ctx context.Context, log logr.Logger) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		d, err := m.client.AppsV1().Deployments(common.CalicoNamespace).Get(ctx, common.TyphaDeploymentName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if d.Status.AvailableReplicas == d.Status.Replicas {
			// Expected replicas active
			return true, nil
		}
		log.V(1).Info(fmt.Sprintf("waiting for typha to %d replicas, currently at %d", d.Status.Replicas, d.Status.AvailableReplicas))
		return false, nil
	})
}

// labelUnmigratedNodes ensures all nodes are labeled. If they do
// not already have the migrated value then the pre-migrated value is set.
func (m *CoreNamespaceMigration) labelUnmigratedNodes(ctx context.Context) error {
	for _, obj := range m.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("never expected index to have anything other than a Node object: %v", obj)
		}
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != nodeSelectorValuePost {
			if err := m.addNodeLabel(ctx, node.Name, nodeSelectorKey, nodeSelectorValuePre); err != nil {
				return err
			}
		}
	}

	return nil
}

// removeNodeMigrationLabelFromNodes removes the label previously added to
// control the migration.
func (m *CoreNamespaceMigration) removeNodeMigrationLabelFromNodes(ctx context.Context) error {
	for _, obj := range m.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("never expected index to have anything other than a Node object: %v", obj)
		}
		if err := m.removeNodeLabel(ctx, node.Name, nodeSelectorKey); err != nil {
			return err
		}
	}

	return nil
}

// ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady updates the calico-node DaemonSet in the
// kube-system namespace with a node selector that will prevent it from being
// deployed to nodes that have been migrated and waits for the daemonset to update.
func (m *CoreNamespaceMigration) ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady(ctx context.Context, log logr.Logger) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		ds, err := m.client.AppsV1().DaemonSets(kubeSystem).Get(ctx, nodeDaemonSetName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if ds.Spec.Template.Spec.NodeSelector == nil {
			ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
		}

		err = m.addNodeSelectorToDaemonSet(ctx, ds, kubeSystem, nodeSelectorKey, nodeSelectorValuePre, log)
		if err != nil {
			if apierrs.IsConflict(err) {
				// Retry on update conflicts.
				return false, nil
			}
			return false, err
		}

		// Get latest kube-system node ds.
		ds, err = m.client.AppsV1().DaemonSets(kubeSystem).Get(ctx, nodeDaemonSetName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if ds.Status.ObservedGeneration != ds.Generation {
			log.Info(fmt.Sprintf("waiting for observed generation (%d) to match object generation (%d)", ds.Status.ObservedGeneration, ds.Generation))
			return false, nil
		}
		if ds.Status.DesiredNumberScheduled != ds.Status.NumberReady {
			log.Info(fmt.Sprintf("waiting for kube-system/calico-node to have %d replicas, currently at %d", ds.Status.DesiredNumberScheduled, ds.Status.NumberReady))
			return false, nil
		}
		log.Info("All kube-system calico/node pods are now ready after nodeSelector update")

		// Successful update
		return true, nil
	})
}

func (m *CoreNamespaceMigration) addNodeSelectorToDaemonSet(ctx context.Context, ds *appsv1.DaemonSet, namespace, key, value string, log logr.Logger) error {
	// Check if nodeSelector is already set
	if _, ok := ds.Spec.Template.Spec.NodeSelector[key]; !ok {
		var patchBytes []byte
		if len(ds.Spec.Template.Spec.NodeSelector) > 0 {
			k := strings.ReplaceAll(key, "/", "~1")

			// This patch does not work when NodeSelectors don't already exist, only use it when some already exist.
			p := []StringPatch{
				{
					Op:    "add",
					Path:  fmt.Sprintf("/spec/template/spec/nodeSelector/%s", k),
					Value: value,
				},
			}

			var err error
			patchBytes, err = json.Marshal(p)
			if err != nil {
				return err
			}
		} else {
			// This patch will overwrite any existing NodeSelectors if any exist so only use it when there are none.
			patchBytes = []byte(fmt.Sprintf(`[ { "op": "add", "path": "/spec/template/spec/nodeSelector", "value": { "%s": "%s" } }]`, key, value))
		}
		log.Info(fmt.Sprintf("Patch NodeSelector with: %s", string(patchBytes)))

		_, err := m.client.AppsV1().DaemonSets(kubeSystem).Patch(ctx, ds.Name, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

// migrateEachNode ensures that the calico-node pods are ready and then update
// the label on one node at a time, ensuring pod becomes ready before starting
// the cycle again. Once the nodes are updated we will get the list of nodes
// that need to be migrated in case there were more added.
func (m *CoreNamespaceMigration) migrateEachNode(ctx context.Context, log logr.Logger) error {
	nodes := m.getNodesToMigrate()
	for len(nodes) > 0 {
		log.WithValues("count", len(nodes)).Info("nodes to migrate")
		for i, node := range nodes {
			// This is to ensure that our new pods are becoming healthy before continuing on.
			// We only wait up to 3 minutes after switching a node to allow the new pod
			// to come up. Also if the operator crashed we don't want to continue
			// updating if the pods are not healthy.
			log.V(1).Info("Waiting for new calico pods to be healthy")
			err := m.waitUntilNodeCanBeMigrated(ctx, log)
			if err == nil {
				log.WithValues("node.Name", node.Name).V(1).Info("Adding label to node")
				err = m.addNodeLabel(ctx, node.Name, nodeSelectorKey, nodeSelectorValuePost)
				if err != nil {
					return fmt.Errorf("setting label on node %s failed; %s", node.Name, err)
				}
				// Pause for a little bit to give a chance for the label changes to propagate.
				time.Sleep(1 * time.Second)
			} else {
				log.WithValues("reason", err).V(1).Info("Failed to check for new healthy pods")
				time.Sleep(10 * time.Second)
			}

			// Wait for the operator-managed Typha deployment to be ready.
			if err := m.waitForOperatorTyphaDeploymentReady(ctx, log); err != nil {
				return fmt.Errorf("failed to wait for operator typha deployment to be ready: %s", err.Error())
			}
			log.V(1).Info("calico-system/calico-typha is running with expected replica count after migrating node")

			log.Info(fmt.Sprintf("Migrated %d out of %d nodes", i+1, len(nodes)))
		}
		// Fetch any new nodes that have been added during migration.
		nodes = m.getNodesToMigrate()
	}
	return nil
}

// getNodesToMigrate returns a list of all nodes that need to be migrated.
func (m *CoreNamespaceMigration) getNodesToMigrate() []*v1.Node {
	nodes := []*v1.Node{}
	for _, obj := range m.indexer.List() {
		node := obj.(*v1.Node)
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != nodeSelectorValuePost {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// waitUntilNodeCanBeMigrated checks the number of desired and ready pods in the kube-system and calico-system
// daemonsets to make sure we don't simultaneously migrate more pods than allowed.
func (m *CoreNamespaceMigration) waitUntilNodeCanBeMigrated(ctx context.Context, log logr.Logger) error {
	return wait.PollUntilContextTimeout(ctx, 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		// num node desired schedule, num node ready, node max unavailable in kube-system
		ksD, ksR, _, err := m.getNumPodsDesiredAndReady(ctx, kubeSystem, nodeDaemonSetName)
		if err != nil {
			return false, err
		}

		// num node desired schedule, num node ready, node max unavailable in calico-system
		csD, csR, csMaxUnavailable, err := m.getNumPodsDesiredAndReady(ctx, common.CalicoNamespace, nodeDaemonSetName)
		if err != nil {
			return false, err
		}

		maxUnavailable := defaultMaxUnavailable

		if csMaxUnavailable != nil {
			numNodesMaxUnavailable, err := intstr.GetValueFromIntOrPercent(csMaxUnavailable, int(ksD+csD), false)
			if err != nil {
				log.Error(err, "Invalid maxUnavailable value, falling back to default of 1")
			} else {
				// Due to the potential rounding down of numNodesMaxUnavailable =  (maxUnavailable %) * ksD+csD, where maxUnavailable is a percentage value,
				// it may resolve to zero. Then we should default back maxUnavailable to 1 on the theory that surge might not work due to quota.
				if numNodesMaxUnavailable < 1 {
					log.Info("Max unavailble nodes calculation resolved to 0, defaulting back to 1 to allow upgrades to continue")
				} else {
					maxUnavailable = int32(numNodesMaxUnavailable)
				}
			}
		}

		// In case of a single node cluster, the ensureTyphaRoom() function scales down the kube-system/calico-typha pod to zero,
		// and it can cause that kube-system/calico-node goes down to CrashLoopBackOff. It can block namespace migration and the below
		// calculation fails as there will be no ready calico-node pods. Handle this special case.
		// Assumptions:
		// - all the nodes are labeled with projectcalico.org/operator-node-migration (pre-operator value)
		// - kube-system/calico-node and calico-system/calico-node daemonsets are using the above nodeSelector
		if ksD == 1 && csD == 0 {
			return true, nil
		}
		// Check that ready pods plus maxUnavailable is MORE than the desired pods so when we migrate
		// one more node we won't go over the maxUnavailable with unready pods.
		if (ksR + csR + maxUnavailable) > (ksD + csD) {
			// Desired pods are ready
			return true, nil
		}

		// Wait for counts to equal
		return false, nil
	})
}

func (m *CoreNamespaceMigration) getNumPodsDesiredAndReady(ctx context.Context, namespace, daemonset string) (int32, int32, *intstr.IntOrString, error) {
	ds, err := m.client.AppsV1().DaemonSets(namespace).Get(ctx, daemonset, metav1.GetOptions{})
	if err != nil {
		return 0, 0, nil, err
	}

	return ds.Status.DesiredNumberScheduled,
		ds.Status.NumberReady,
		ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable,
		nil
}

// addNodeLabels adds the specified labels to the named node. Perform
// Get/Check/Update so that it always working on latest version.
// If node labels has been set already, do nothing.
func (m *CoreNamespaceMigration) addNodeLabel(ctx context.Context, nodeName, key, value string) error {
	return wait.PollUntilContextTimeout(ctx, 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		node, err := m.client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := true
		if curr, ok := node.Labels[key]; ok && curr == value {
			needUpdate = false
		}

		k := strings.ReplaceAll(key, "/", "~1")

		lp := []StringPatch{{
			Op:    "add",
			Path:  fmt.Sprintf("/metadata/labels/%s", k),
			Value: value,
		}}

		patchBytes, err := json.Marshal(lp)
		if err != nil {
			return false, err
		}

		if needUpdate {
			_, err := m.client.CoreV1().Nodes().Patch(ctx, node.Name, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

type StringPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

// Remove node labels from node. Perform Get/Check/Update so that it always working on the
// most recent version of the resource.
// If node labels do not exist, do nothing.
func (m *CoreNamespaceMigration) removeNodeLabel(ctx context.Context, nodeName, key string) error {
	return wait.PollUntilContextTimeout(ctx, 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		node, err := m.client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		if _, ok := node.Labels[key]; ok {
			needUpdate = true
		}

		// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
		k := strings.ReplaceAll(key, "/", "~1")
		lp := []StringPatch{{
			Op:   "remove",
			Path: fmt.Sprintf("/metadata/labels/%s", k),
		}}

		patchBytes, err := json.Marshal(lp)
		if err != nil {
			return false, err
		}

		if err != nil {
			return false, fmt.Errorf("patch to remove labels failed: %v", err)
		}

		if needUpdate {
			_, err = m.client.CoreV1().Nodes().Patch(ctx, node.Name, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// waitForOperatorCalicoNodeDaemonsetReady waits until the 'new' calico-node daemonset in
// the calico-system namespace is ready before continuing, it will wait up to
// 1 minutes before returning with an error.
func (m *CoreNamespaceMigration) waitForOperatorCalicoNodeDaemonsetReady(ctx context.Context, log logr.Logger) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		d, err := m.client.AppsV1().DaemonSets(common.CalicoNamespace).Get(ctx, nodeDaemonSetName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Status.DesiredNumberScheduled == d.Status.UpdatedNumberScheduled &&
			d.Status.DesiredNumberScheduled == d.Status.NumberReady &&
			d.Status.DesiredNumberScheduled == d.Status.NumberAvailable {
			// Expected replicas active
			return true, nil
		}
		log.Info(fmt.Sprintf("waiting for calico-node to %d replicas, ready at %d, up-to-date at %d, available at %d",
			d.Status.DesiredNumberScheduled, d.Status.NumberReady, d.Status.UpdatedNumberScheduled, d.Status.NumberAvailable))
		return false, nil
	})
}
