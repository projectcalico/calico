package bgp

import (
	"context"
	"fmt"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/v3/apis/projectcalico/v3"
	"github.com/projectcalico/api/v3/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

// requireNonVXLANCluster checks that no IP pool uses VXLAN encapsulation. Tests that
// disable the BGP mesh and expect connectivity to break cannot work on VXLAN clusters
// because Felix programs VXLAN tunnel routes independently of BGP.
func requireNonVXLANCluster(cli ctrlclient.Client) {
	pools := &v3.IPPoolList{}
	err := cli.List(context.Background(), pools)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error listing IP pools")

	for _, pool := range pools.Items {
		switch pool.Spec.VXLANMode {
		case v3.VXLANModeAlways, v3.VXLANModeCrossSubnet:
			framework.Failf(
				"This test requires BGP full mesh as the sole routing mechanism, and cannot run with VXLAN enabled (pool %s uses VXLANMode %s)",
				pool.Name, pool.Spec.VXLANMode,
			)
		}
	}
}

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

// BGPStatusMonitor manages CalicoNodeStatus resources for observing BGP session
// state during tests. Create one per test suite via NewBGPStatusMonitor, which
// creates the status resources and registers cleanup. Then use Log, WaitForEstablished,
// and WaitForNoEstablished to orchestrate test assertions around BGP convergence.
type BGPStatusMonitor struct {
	cli       ctrlclient.Client
	nodeNames []string
}

// NewBGPStatusMonitor creates CalicoNodeStatus resources for all nodes in the cluster
// with BGP and Routes classes enabled and a fast (1s) update period. Registers a
// DeferCleanup to remove them when the test completes.
func NewBGPStatusMonitor(cli ctrlclient.Client) *BGPStatusMonitor {
	nodes := &corev1.NodeList{}
	err := cli.List(context.Background(), nodes)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error listing nodes")

	m := &BGPStatusMonitor{cli: cli}
	for _, node := range nodes.Items {
		status := &v3.CalicoNodeStatus{
			ObjectMeta: metav1.ObjectMeta{Name: node.Name},
			Spec: v3.CalicoNodeStatusSpec{
				Node: node.Name,
				Classes: []v3.NodeStatusClassType{
					v3.NodeStatusClassTypeBGP,
					v3.NodeStatusClassTypeRoutes,
				},
				UpdatePeriodSeconds: ptr.To[uint32](1),
			},
		}
		err := cli.Create(context.Background(), status)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error creating CalicoNodeStatus for node %s", node.Name)
		m.nodeNames = append(m.nodeNames, node.Name)
	}

	ginkgo.DeferCleanup(func() {
		for _, name := range m.nodeNames {
			status := &v3.CalicoNodeStatus{ObjectMeta: metav1.ObjectMeta{Name: name}}
			if err := cli.Delete(context.Background(), status); err != nil {
				logrus.WithError(err).Warnf("Failed to delete CalicoNodeStatus %s", name)
			}
		}
	})

	return m
}

// Log dumps the current BGP session and route state for all nodes. Useful for
// diagnostics inside Eventually loops or at key test checkpoints.
func (m *BGPStatusMonitor) Log() {
	for _, name := range m.nodeNames {
		status := &v3.CalicoNodeStatus{}
		err := m.cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, status)
		if err != nil {
			logrus.WithError(err).Warnf("Failed to get CalicoNodeStatus for %s", name)
			continue
		}

		bgp := status.Status.BGP
		logrus.Infof("[BGP] Node %s: established_v4=%d not_established_v4=%d established_v6=%d not_established_v6=%d last_updated=%s",
			name,
			bgp.NumberEstablishedV4, bgp.NumberNotEstablishedV4,
			bgp.NumberEstablishedV6, bgp.NumberNotEstablishedV6,
			status.Status.LastUpdated.Time,
		)
		for _, peer := range bgp.PeersV4 {
			logrus.Infof("[BGP]   Node %s peer %s type=%s state=%s since=%s", name, peer.PeerIP, peer.Type, peer.State, peer.Since)
		}
		for _, route := range status.Status.Routes.RoutesV4 {
			logrus.Infof("[BGP]   Node %s route: %s via %s type=%s", name, route.Destination, route.Gateway, route.Type)
		}
	}
}

// WaitForEstablished waits until all nodes have at least one established BGP peer
// and no non-established peers. Logs BGP state on each poll for diagnostics.
func (m *BGPStatusMonitor) WaitForEstablished() {
	ginkgo.By("Waiting for all BGP sessions to be established")
	EventuallyWithOffset(1, func() error {
		for _, name := range m.nodeNames {
			status := &v3.CalicoNodeStatus{}
			if err := m.cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, status); err != nil {
				return fmt.Errorf("failed to get CalicoNodeStatus for %s: %w", name, err)
			}
			bgp := status.Status.BGP
			if bgp.NumberEstablishedV4+bgp.NumberEstablishedV6 == 0 {
				return fmt.Errorf("node %s: no BGP peers established yet", name)
			}
			if bgp.NumberNotEstablishedV4+bgp.NumberNotEstablishedV6 > 0 {
				return fmt.Errorf("node %s: %d v4 + %d v6 peers not established",
					name, bgp.NumberNotEstablishedV4, bgp.NumberNotEstablishedV6)
			}
		}
		return nil
	}, "2m", "1s").Should(Succeed(), "BGP sessions did not all reach Established state")
}

// WaitForNoPeers waits until no node reports any established BGP peers of any type.
// Logs BGP state on each poll for diagnostics.
func (m *BGPStatusMonitor) WaitForNoPeers() {
	ginkgo.By("Waiting for all BGP peers to be removed")
	EventuallyWithOffset(1, func() error {
		for _, name := range m.nodeNames {
			status := &v3.CalicoNodeStatus{}
			if err := m.cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, status); err != nil {
				return fmt.Errorf("failed to get CalicoNodeStatus for %s: %w", name, err)
			}
			bgp := status.Status.BGP
			total := bgp.NumberEstablishedV4 + bgp.NumberNotEstablishedV4 + bgp.NumberEstablishedV6 + bgp.NumberNotEstablishedV6
			if total > 0 {
				m.Log()
				return fmt.Errorf("node %s still has %d BGP peers", name, total)
			}
		}
		return nil
	}, "2m", "1s").Should(Succeed(), "BGP peers still present")
}

// WaitForNoMeshPeers waits until no node reports any NodeMesh BGP peers. This is
// used after disabling the node-to-node mesh to confirm sessions have torn down.
// Logs BGP state on each poll for diagnostics.
func (m *BGPStatusMonitor) WaitForNoMeshPeers() {
	ginkgo.By("Waiting for all NodeMesh BGP sessions to be torn down")
	EventuallyWithOffset(1, func() error {
		for _, name := range m.nodeNames {
			status := &v3.CalicoNodeStatus{}
			if err := m.cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, status); err != nil {
				return fmt.Errorf("failed to get CalicoNodeStatus for %s: %w", name, err)
			}
			for _, peer := range status.Status.BGP.PeersV4 {
				if peer.Type == v3.BGPPeerTypeNodeMesh {
					m.Log()
					return fmt.Errorf("node %s still has NodeMesh peer %s (state=%s)", name, peer.PeerIP, peer.State)
				}
			}
			for _, peer := range status.Status.BGP.PeersV6 {
				if peer.Type == v3.BGPPeerTypeNodeMesh {
					return fmt.Errorf("node %s still has NodeMesh v6 peer %s (state=%s)", name, peer.PeerIP, peer.State)
				}
			}
		}
		return nil
	}, "2m", "1s").Should(Succeed(), "NodeMesh BGP sessions still present after disabling mesh")
}
