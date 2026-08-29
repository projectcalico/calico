// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package typhaautoscaler

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("Test typha autoscaler ", func() {
	var statusManager *status.MockStatus
	var c client.Client
	var ctx context.Context
	var cancel context.CancelFunc
	var ta *Autoscaler

	BeforeEach(func() {
		ta = nil
		statusManager = new(status.MockStatus)

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		ctx, cancel = context.WithCancel(context.Background())
		Expect(c.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: common.CalicoNamespace},
		})).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Cancel the context and wait for the autoscaler goroutine to exit before the next spec
		// runs. Otherwise a leaked goroutine can call SetDegraded on this spec's mock after the
		// spec has ended, panicking a later, unrelated spec.
		cancel()
		if ta != nil {
			ta.WaitForShutdown()
		}
	})

	It("should initialize an autoscaler", func() {
		createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux"})

		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager)
		ta.Start(ctx)
	})

	It("should get the correct number of nodes", func() {
		n1 := createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node2", map[string]string{"kubernetes.io/os": "linux"})

		schedulableNodes, linuxNodes, err := nodeCounts(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(schedulableNodes).To(Equal(2))
		Expect(linuxNodes).To(Equal(2))

		n1.Spec.Unschedulable = true
		Expect(c.Update(ctx, n1)).NotTo(HaveOccurred())

		schedulableNodes, linuxNodes, err = nodeCounts(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(schedulableNodes).To(Equal(1))
		Expect(linuxNodes).To(Equal(1))
	})

	It("should scale the Typha up and down in response to the number of schedulable nodes", func() {
		createTypha(ctx, c, common.TyphaDeploymentName)

		// Create a few nodes
		createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node2", map[string]string{"kubernetes.io/os": "linux"})

		// Create the autoscaler and run it
		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager, OptionPeriod(10*time.Millisecond))
		ta.Start(ctx)

		// For clusters smaller than 3 nodes we only expect 1 replica.
		verifyTyphaReplicas(c, 1)

		// For three and four node clusters, we expect 2.
		n3 := createNode(ctx, c, "node3", map[string]string{"kubernetes.io/os": "linux"})
		verifyTyphaReplicas(c, 2)
		createNode(ctx, c, "node4", map[string]string{"kubernetes.io/os": "linux"})
		verifyTyphaReplicas(c, 2)

		// For > 4 nodes, we expect redundancy with 3 replicas.
		createNode(ctx, c, "node5", map[string]string{"kubernetes.io/os": "linux"})
		verifyTyphaReplicas(c, 3)

		// Verify that making a node unschedulable updates replicas. Should bring us back
		// down to 4 node scale.
		n3.Spec.Unschedulable = true
		Expect(c.Update(ctx, n3)).NotTo(HaveOccurred())
		verifyTyphaReplicas(c, 2)
	})

	It("should not ignore non-migrated nodes in its count", func() {
		createTypha(ctx, c, common.TyphaDeploymentName)

		// Create five nodes, one of which is not yet migrated
		createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"})
		createNode(ctx, c, "node2", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"})
		createNode(ctx, c, "node3", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"})
		createNode(ctx, c, "node4", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"})
		createNode(ctx, c, "node5", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "pre-operator"})

		// Create the autoscaler and run it
		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager, OptionPeriod(10*time.Millisecond))
		ta.Start(ctx)

		verifyTyphaReplicas(c, 3)
	})

	It("should ignore aks virtual nodes in its count", func() {
		createTypha(ctx, c, common.TyphaDeploymentName)

		// Create five nodes, one of which is a virtual-kubelet
		createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node2", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node3", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node4", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node5", map[string]string{"kubernetes.io/os": "linux", "kubernetes.azure.com/cluster": "foo", "type": "virtual-kubelet"})

		// Create the autoscaler and run it
		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager, OptionPeriod(10*time.Millisecond))
		ta.Start(ctx)

		// normally we'd expect to see three replicas for five nodes, but since one node is a virtual-kubelet,
		// we should still only expect two
		verifyTyphaReplicas(c, 2)
	})

	It("should scale the non-cluster-host Typha by host endpoint count", func() {
		name := common.TyphaDeploymentName + "-noncluster-host"
		createTypha(ctx, c, name)

		// Only the host endpoints kube-controllers did not create should count.
		createHostEndpoint(ctx, c, "hep1", nil)
		createHostEndpoint(ctx, c, "hep2", nil)
		createHostEndpoint(ctx, c, "hep3", nil)
		createHostEndpoint(ctx, c, "auto-hep", map[string]string{hepCreatedLabelKey: hepCreatedLabelValue})

		ta = New(c, name, HostEndpointReplicaCounter, statusManager, OptionPeriod(10*time.Millisecond))
		ta.Start(ctx)

		verifyTyphaReplicasFor(c, name, 2)
	})

	It("should be degraded if there's not enough linux nodes", func() {
		createTypha(ctx, c, common.TyphaDeploymentName)

		statusManager.On("SetDegraded", operator.ResourceScalingError, "Failed to autoscale typha - not enough linux nodes to schedule typha pods on, require 3 and have 2", mock.Anything, mock.Anything)

		// Create a few nodes
		createNode(ctx, c, "node1", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node2", map[string]string{"kubernetes.io/os": "linux"})
		createNode(ctx, c, "node3", map[string]string{"kubernetes.io/os": "windows"})
		createNode(ctx, c, "node4", map[string]string{"kubernetes.io/os": "windows"})
		createNode(ctx, c, "node5", map[string]string{"kubernetes.io/os": "windows"})

		// Create the autoscaler and run it
		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager, OptionPeriod(10*time.Millisecond))
		ta.Start(ctx)

		// This blocks until the first run is done.
		ta.IsDegraded()

		statusManager.AssertExpectations(GinkgoT())
	})

	It("should not autoscale or report degraded once its context is cancelled", func() {
		// statusManager has no SetDegraded expectation configured, so the mock panics if it's
		// called. With zero linux nodes the startup autoscale would normally report degraded, so
		// a cancelled autoscaler that still runs the startup autoscale would panic here.
		cancelledCtx, cancelStart := context.WithCancel(context.Background())
		cancelStart()

		ta = New(c, common.TyphaDeploymentName, NodeReplicaCounter, statusManager)
		ta.Start(cancelledCtx)

		// The goroutine should observe the cancelled context and exit without autoscaling.
		ta.WaitForShutdown()
		statusManager.AssertNotCalled(GinkgoT(), "SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
})

func createNode(ctx context.Context, c client.Client, name string, labels map[string]string) *corev1.Node {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	ExpectWithOffset(1, c.Create(ctx, node)).NotTo(HaveOccurred())
	return node
}

func createTypha(ctx context.Context, c client.Client, name string) {
	var replicas int32 = 0
	typha := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: common.CalicoNamespace},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
	}
	ExpectWithOffset(1, c.Create(ctx, typha)).NotTo(HaveOccurred())
}

func createHostEndpoint(ctx context.Context, c client.Client, name string, labels map[string]string) {
	hep := &v3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	ExpectWithOffset(1, c.Create(ctx, hep)).NotTo(HaveOccurred())
}

func verifyTyphaReplicas(c client.Client, expectedReplicas int) {
	verifyTyphaReplicasFor(c, common.TyphaDeploymentName, expectedReplicas)
}

func verifyTyphaReplicasFor(c client.Client, name string, expectedReplicas int) {
	Eventually(func() int32 {
		typha := &appsv1.Deployment{}
		key := types.NamespacedName{Name: name, Namespace: common.CalicoNamespace}
		Expect(c.Get(context.Background(), key, typha)).NotTo(HaveOccurred())
		// Just return an invalid number that will never match an expected replica count.
		if typha.Spec.Replicas == nil {
			return -1
		}
		return *typha.Spec.Replicas
	}, 5*time.Second).Should(BeEquivalentTo(expectedReplicas))
}
