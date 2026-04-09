package bgp

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

// ensureInitialBGPConfig checks for an existing BGPConfiguration resource and ensures that full mesh BGP is enabled.
// It returns a cleanup function to restore the original state after the test.
func ensureInitialBGPConfig(cli ctrlclient.Client) func() {
	// Ensure full mesh BGP is functioning before each test.
	initialConfig := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, initialConfig)
	if errors.IsNotFound(err) {
		// Not found - simply create a new one, enabling full mesh (the default behavior). Ideally, our product code
		// would do this automatically, but we do it here until it does.
		By("Creating default BGPConfiguration suitable for tests")
		err = cli.Create(context.Background(), &v3.BGPConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: v3.BGPConfigurationSpec{
				NodeToNodeMeshEnabled: ptr.To(true),
			},
		})
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error creating BGPConfiguration resource")

		return func() {
			By("Deleting BGPConfiguration created for tests")
			err := cli.Delete(context.Background(), &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
			ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error deleting BGPConfiguration resource")
		}
	}

	By("Ensuring full mesh BGP is enabled in existing BGPConfiguration")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
	ExpectWithOffset(1, initialConfig.Spec.NodeToNodeMeshEnabled).NotTo(BeNil(), "nodeToNodeMeshEnabled is not configured in BGPConfiguration")
	ExpectWithOffset(1, *initialConfig.Spec.NodeToNodeMeshEnabled).To(BeTrue(), "nodeToNodeMeshEnabled is not enabled in BGPConfiguration")

	return func() {
		By("Restoring initial BGPConfiguration")
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
	By("Disabling full mesh BGP")
	config := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
	config.Spec.NodeToNodeMeshEnabled = ptr.To(false)
	err = cli.Update(context.Background(), config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource")
}

func setASNumber(cli ctrlclient.Client, asn numorstring.ASNumber) {
	By("Setting AS number in BGPConfiguration")
	config := &v3.BGPConfiguration{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
	config.Spec.ASNumber = ptr.To(numorstring.ASNumber(asn))
	err = cli.Update(context.Background(), config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource")
}

func setNodeAsRouteReflector(cli ctrlclient.Client, rrNode *corev1.Node, rrClusterID string) {
	By(fmt.Sprintf("Using node %s as a route reflector", rrNode.Name))
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

	DeferCleanup(func() {
		setNodeAsNotRouteReflector(cli, rrNode)
	})
}

func setNodeAsNotRouteReflector(cli ctrlclient.Client, rrNode *corev1.Node) {
	By(fmt.Sprintf("Removing route reflector role from node %s", rrNode.Name))
	prePatch := ctrlclient.MergeFrom(rrNode.DeepCopy())
	delete(rrNode.Labels, resources.RouteReflectorClusterIDAnnotation)
	delete(rrNode.Annotations, resources.RouteReflectorClusterIDAnnotation)
	err := cli.Patch(context.Background(), rrNode, prePatch)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error removing route reflector label from node")
}

func deleteCalicoNode(cli ctrlclient.Client, node *corev1.Node) {
	By(fmt.Sprintf("Simulating failure of node %s by deleting calico-node Pod", node.Name))

	// Get the calico/node Pod on the node.
	podList := &corev1.PodList{}
	err := cli.List(context.Background(), podList, ctrlclient.MatchingLabels{"k8s-app": "calico-node"}, ctrlclient.MatchingFields{"spec.nodeName": node.Name})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error listing calico-node Pods on node")
	ExpectWithOffset(1, len(podList.Items)).To(BeNumerically(">", 0), "No calico-node Pod found on node")

	// Delete the calico/node Pod to simulate failure.
	err = cli.Delete(context.Background(), &podList.Items[0])
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error deleting calico-node Pod to simulate node failure")
}
