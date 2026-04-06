package bgp

import (
	"context"
	"fmt"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

// ensureInitialBGPConfig updates the default BGPConfiguration to ensures that full mesh BGP is enabled.
// It returns a cleanup function to restore the original state after the test.
func ensureInitialBGPConfig(cli ctrlclient.Client) func() {
	// Ensure full mesh BGP is functioning before each test.
	initialConfig := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, initialConfig)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying default BGPConfiguration resource")

	updated := false
	updatedConfig := *initialConfig
	if initialConfig.Spec.NodeToNodeMeshEnabled == nil || !*initialConfig.Spec.NodeToNodeMeshEnabled {
		updatedConfig.Spec.NodeToNodeMeshEnabled = ptr.To(true)
		err = cli.Update(context.Background(), &updatedConfig)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource to enable mesh")
		updated = true

		err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, &updatedConfig)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying default BGPConfiguration resource")
	}

	ginkgo.By("Ensuring full mesh BGP is enabled in existing BGPConfiguration")
	ExpectWithOffset(1, updatedConfig.Spec.NodeToNodeMeshEnabled).NotTo(BeNil(), "nodeToNodeMeshEnabled is not configured in BGPConfiguration")
	ExpectWithOffset(1, *updatedConfig.Spec.NodeToNodeMeshEnabled).To(BeTrue(), "nodeToNodeMeshEnabled is not enabled in BGPConfiguration")

	return func() {
		if !updated {
			return
		}
		ginkgo.By("Restoring initial BGPConfiguration")
		// Query the resource again to get the latest resource version.
		currentConfig := &v3.BGPConfiguration{}
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, currentConfig)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource for restoration")
		initialConfig.ResourceVersion = currentConfig.ResourceVersion
		err = cli.Update(context.Background(), initialConfig)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error restoring initial BGPConfiguration resource")
	}
}

func disableFullMesh(cli ctrlclient.Client) {
	ginkgo.By("Disabling full mesh BGP")
	config := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
	config.Spec.NodeToNodeMeshEnabled = ptr.To(false)
	err = cli.Update(context.Background(), config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource")
}

func setASNumber(cli ctrlclient.Client, asn numorstring.ASNumber) {
	ginkgo.By("Setting AS number in BGPConfiguration")
	config := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
	config.Spec.ASNumber = ptr.To(numorstring.ASNumber(asn))
	err = cli.Update(context.Background(), config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource")
}

func setNodeAsRouteReflector(cli ctrlclient.Client, rrNode *corev1.Node, rrClusterID string) {
	ginkgo.By(fmt.Sprintf("Using node %s as a route reflector", rrNode.Name))
	prePatch := ctrlclient.MergeFrom(rrNode.DeepCopy())

	// Adding the cluster ID as an annotation tells Calico to configure the node as a route reflector.
	if rrNode.Annotations == nil {
		rrNode.Annotations = map[string]string{}
	}

	// Adding it as a label allows us to select the node in a BGPPeer.
	if rrNode.Labels == nil {
		rrNode.Labels = map[string]string{}
	}

	rrNode.Labels[resources.RouteReflectorClusterIDAnnotation] = rrClusterID
	rrNode.Annotations[resources.RouteReflectorClusterIDAnnotation] = rrClusterID
	err := cli.Patch(context.Background(), rrNode, prePatch)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error marking node as route reflector")

	ginkgo.DeferCleanup(func() {
		setNodeAsNotRouteReflector(cli, rrNode)
	})
}

func setNodeAsNotRouteReflector(cli ctrlclient.Client, rrNode *corev1.Node) {
	ginkgo.By(fmt.Sprintf("Removing route reflector role from node %s", rrNode.Name))
	prePatch := ctrlclient.MergeFrom(rrNode.DeepCopy())
	delete(rrNode.Labels, resources.RouteReflectorClusterIDAnnotation)
	delete(rrNode.Annotations, resources.RouteReflectorClusterIDAnnotation)
	err := cli.Patch(context.Background(), rrNode, prePatch)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error removing route reflector label from node")
}

func deleteCalicoNode(cli ctrlclient.Client, node *corev1.Node) {
	ginkgo.By(fmt.Sprintf("Simulating failure of node %s by deleting calico-node Pod", node.Name))

	// Get the calico/node Pod on the node.
	podList := &corev1.PodList{}
	err := cli.List(context.Background(), podList, ctrlclient.MatchingLabels{"k8s-app": "calico-node"}, ctrlclient.MatchingFields{"spec.nodeName": node.Name})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error listing calico-node Pods on node")
	ExpectWithOffset(1, len(podList.Items)).To(BeNumerically(">", 0), "No calico-node Pod found on node")

	// Delete the calico/node Pod to simulate failure.
	err = cli.Delete(context.Background(), &podList.Items[0])
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error deleting calico-node Pod to simulate node failure")
}

// waitForBGPEstablished waits until the expected number of BGPPeers are established for the given nodes
// using CalicoNodeStatus resources.
func waitForBGPEstablished(cli ctrlclient.Client, nodes ...corev1.Node) {
	for _, node := range nodes {
		waitForBGPEstablishedForNode(cli, node.Name)
	}
}

func waitForBGPEstablishedForNode(cli ctrlclient.Client, node string) {
	// Create a CalicoNodeStatus resource to verify BGPPeer status.
	status := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: node},
		Spec: v3.CalicoNodeStatusSpec{
			Node:    node,
			Classes: []v3.NodeStatusClassType{v3.NodeStatusClassTypeBGP},

			// Set a short update period to speed up the test.
			UpdatePeriodSeconds: ptr.To[uint32](1),
		},
	}
	err := cli.Create(context.Background(), status)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error creating CalicoNodeStatus resource")

	// Make sure we clean up the CalicoNodeStatus resource after we're done.
	defer func() {
		err := cli.Delete(context.Background(), status)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error deleting CalicoNodeStatus resource")
	}()

	// Expect the CalicoNodeStatus to report all BGPPeers as established.
	EventuallyWithOffset(1, func() error {
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: node}, status)
		if err != nil {
			return err
		}
		if status.Status.BGP.NumberEstablishedV4+status.Status.BGP.NumberEstablishedV6 == 0 {
			return fmt.Errorf("no BGPPeers are established yet")
		}
		if status.Status.BGP.NumberNotEstablishedV4+status.Status.BGP.NumberNotEstablishedV6 > 0 {
			return fmt.Errorf("not all BGPPeers are established (not established: v4=%d, v6=%d)",
				status.Status.BGP.NumberNotEstablishedV4, status.Status.BGP.NumberNotEstablishedV6)
		}
		return nil
	}, "1m", "1s").ShouldNot(HaveOccurred(), "BGPPeer count did not reach expected value")
}
