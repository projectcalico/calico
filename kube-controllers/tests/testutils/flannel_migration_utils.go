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

// The utils in this file are specific to the policy controller,
// and are not expected to be shared across projects.

package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"

	. "github.com/onsi/gomega"
)

// Run Flannel migration controller on a node.
func RunFlannelMigrationController(kconfigfile string, nodeName, subnetEnv string, waitBeforeStart, waitBeforeExit int) *containers.Container {
	return containers.Run("flannel-migration-controller",
		containers.RunOpts{AutoRemove: true},
		"--privileged",
		"-e", "DATASTORE_TYPE=kubernetes",
		"-e", "ENABLED_CONTROLLERS=flannelmigration",
		"-e", "LOG_LEVEL=debug",
		"-e", fmt.Sprintf("POD_NODE_NAME=%s", nodeName),
		"-e", fmt.Sprintf("FLANNEL_SUBNET_ENV=%s", subnetEnv),
		"-e", fmt.Sprintf("DEBUG_WAIT_BEFORE_START=%d", waitBeforeStart),
		"-e", fmt.Sprintf("DEBUG_WAIT_BEFORE_EXIT=%d", waitBeforeExit),
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		os.Getenv("MIGRATION_CONTAINER_NAME"))
}

type FlannelNode struct {
	PodCidr  string
	BackEnd  string
	VtepMac  string
	PublicIP string
}

func newFlannelNode(podCidr, backend, mac, ip string) FlannelNode {
	return FlannelNode{
		PodCidr:  podCidr,
		BackEnd:  backend,
		VtepMac:  mac,
		PublicIP: ip,
	}
}

func (n FlannelNode) getFlannelAnnotations() map[string]string {
	jsonString, err := json.Marshal(map[string]string{"VtepMac": n.VtepMac})
	Expect(err).ShouldNot(HaveOccurred())
	return map[string]string{
		"flannel.alpha.coreos.com/backend-data": string(jsonString),
		"flannel.alpha.coreos.com/backend-type": n.BackEnd,
		"flannel.alpha.coreos.com/public-ip":    n.PublicIP,
	}
}

type FlannelCluster struct {
	k8sClient    *kubernetes.Clientset
	Nodes        map[string]*v1.Node
	FlannelNodes map[string]FlannelNode
	Network      string
}

func NewFlannelCluster(k8sClient *kubernetes.Clientset, network string) *FlannelCluster {
	return &FlannelCluster{
		k8sClient:    k8sClient,
		Network:      network,
		Nodes:        map[string]*v1.Node{},
		FlannelNodes: map[string]FlannelNode{},
	}
}

func (f *FlannelCluster) Reset() {
	// Delete the Kubernetes node.
	for nodeName := range f.FlannelNodes {
		err := f.k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			_, err := f.k8sClient.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
			return apierrs.IsNotFound(err)
		}, time.Second*2, 500*time.Millisecond).Should(Equal(true))
	}
	f = nil
}

func (f *FlannelCluster) AddFlannelNode(nodeName, podCidr, backend, mac, ip string, labels map[string]string, isMaster bool) *v1.Node {
	defaultLabels := map[string]string{"kubernetes.io/os": "linux"}
	if isMaster {
		defaultLabels["node-role.kubernetes.io/master"] = ""
	}
	for k, v := range labels {
		defaultLabels[k] = v
	}

	flannelNode := newFlannelNode(podCidr, backend, mac, ip)

	node, err := f.k8sClient.CoreV1().Nodes().Create(context.Background(),
		&v1.Node{
			TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:        nodeName,
				Labels:      defaultLabels,
				Annotations: flannelNode.getFlannelAnnotations(),
			},
			Spec: v1.NodeSpec{
				PodCIDR: podCidr,
			},
		},
		metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	_, err = f.k8sClient.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	f.Nodes[nodeName] = node
	f.FlannelNodes[nodeName] = flannelNode

	return node
}

func (f *FlannelCluster) AddDefaultCalicoConfigMap() {
	_, err := f.k8sClient.CoreV1().ConfigMaps(metav1.NamespaceSystem).Create(context.Background(),
		&v1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "calico-config",
			},
			Data: map[string]string{"veth_mtu": "1450"},
		},
		metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (f *FlannelCluster) AddFlannelDaemonset(name string) {
	var gracePeriodSecs int64
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "flannel"},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceSystem,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &selector,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "flannel",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:    "kube-flannel",
							Image:   "quay.io/coreos/flannel:v0.11.0-amd64",
							Command: []string{"/opt/bin/flanneld"},
						},
					},
					NodeSelector:                  map[string]string{"kubernetes.io/arch": "amd64"},
					NodeName:                      "random-name-to-avoid-schedule",
					Tolerations:                   []v1.Toleration{},
					TerminationGracePeriodSeconds: &gracePeriodSecs,
				},
			},
		},
	}

	_, err := f.k8sClient.AppsV1().DaemonSets(metav1.NamespaceSystem).Create(context.Background(), ds, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (f *FlannelCluster) AddCalicoDaemonset(name string) {
	var gracePeriodSecs int64
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"k8s-app": "calico-node"},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceSystem,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &selector,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "calico-node",
					},
				},
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Name:  "install-cni",
							Image: "calico/cni:v3.8.1",
							Env: []v1.EnvVar{
								{
									Name:  "CNI_CONF_NAME",
									Value: "10-calico.conflist",
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:  "calico-node",
							Image: "calico/node:v3.8.1",
						},
					},
					NodeSelector:                  map[string]string{"kubernetes.io/arch": "amd64", "projectcalico.org/node-network-during-migration": "calico"},
					NodeName:                      "random-name-to-avoid-schedule",
					Tolerations:                   []v1.Toleration{},
					TerminationGracePeriodSeconds: &gracePeriodSecs,
				},
			},
		},
	}

	_, err := f.k8sClient.AppsV1().DaemonSets(metav1.NamespaceSystem).Create(context.Background(), ds, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (f *FlannelCluster) AddCanalDaemonset(name string) {
	var gracePeriodSecs int64
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"k8s-app": "canal"},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceSystem,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &selector,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "canal",
					},
				},
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Name:  "install-cni",
							Image: "calico/cni:v3.8.1",
							Env: []v1.EnvVar{
								{
									Name:  "CNI_CONF_NAME",
									Value: "10-canal.conflist",
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:  "calico-node",
							Image: "calico/node:v3.8.1",
						},
						{
							Name:    "kube-flannel",
							Image:   "quay.io/coreos/flannel:v0.11.0-amd64",
							Command: []string{"/opt/bin/flanneld"},
						},
					},
					NodeSelector:                  map[string]string{"kubernetes.io/arch": "amd64", "projectcalico.org/node-network-during-migration": "calico"},
					NodeName:                      "random-name-to-avoid-schedule",
					Tolerations:                   []v1.Toleration{},
					TerminationGracePeriodSeconds: &gracePeriodSecs,
				},
			},
		},
	}

	_, err := f.k8sClient.AppsV1().DaemonSets(metav1.NamespaceSystem).Create(context.Background(), ds, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}
