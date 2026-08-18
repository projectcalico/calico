// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package networking

import (
	"context"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/metrics"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// defaultFelixMetricsPort is Felix's default Prometheus port, used when the
// FelixConfiguration does not pin one.
const defaultFelixMetricsPort = 9091

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Wireguard"),
	describe.WithCategory(describe.Networking),
	"WireGuard tests",
	func() {
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var testServer conncheck.Server
		var testClient conncheck.Client
		var scraper *metrics.MetricScraper
		var clientNode string

		f := utils.NewDefaultFramework("wireguard")

		ginkgo.BeforeEach(func() {
			if windows.ClusterIsWindows() {
				framework.Failf("WireGuard tests are not implemented on Windows")
			}

			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			felixConfig := &v3.FelixConfiguration{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, felixConfig)
			Expect(err).NotTo(HaveOccurred(), "Error querying FelixConfiguration")
			Expect(felixConfig.Spec.WireguardEnabled).NotTo(BeNil(), "WireGuard is not enabled in the cluster")
			Expect(*felixConfig.Spec.WireguardEnabled).To(BeTrue(), "WireGuard is not enabled in the cluster")

			// The client and server must land on different nodes for their traffic
			// to cross a WireGuard tunnel at all.
			utils.RequireNodeCount(f, 2)

			metricsPort := defaultFelixMetricsPort
			if felixConfig.Spec.PrometheusMetricsPort != nil {
				metricsPort = *felixConfig.Spec.PrometheusMetricsPort
			}

			cleanupMetrics, err := metrics.EnsurePrometheusMetricsEnabled(cli)
			if cleanupMetrics != nil {
				ginkgo.DeferCleanup(cleanupMetrics)
			}
			Expect(err).NotTo(HaveOccurred())

			checker = conncheck.NewConnectionTester(f)
			testServer = conncheck.NewServer("server", f.Namespace, conncheck.WithServerPodCustomizer(conncheck.AvoidEachOther))
			testClient = conncheck.NewClient("client", f.Namespace, conncheck.WithClientCustomizer(conncheck.AvoidEachOther))
			checker.AddServer(testServer)
			checker.AddClient(testClient)
			checker.Deploy()

			clientNode = testClient.Pod().Spec.NodeName
			Expect(clientNode).NotTo(BeEmpty(), "Client pod has not been scheduled to a node")
			Expect(testServer.Pod().Spec.NodeName).NotTo(Equal(clientNode), "Client and server pods share a node")

			var cleanupScraper func() error
			scraper, cleanupScraper, err = metrics.NewMetricScraper(f, nodeInternalIP(f, clientNode), metricsPort)
			Expect(err).NotTo(HaveOccurred())
			ginkgo.DeferCleanup(cleanupScraper)
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
		})

		ginkgo.It("should carry pod traffic between nodes over the tunnel", func() {
			bytesSent := scraper.MetricSum("wireguard_bytes_sent")

			ginkgo.By("Reading the sending node's WireGuard byte counter")
			var before float64
			Eventually(func() error {
				var err error
				before, err = bytesSent()
				return err
			}).WithTimeout(90*time.Second).WithPolling(5*time.Second).Should(Succeed(),
				"Felix on node %s should report WireGuard traffic to its peers", clientNode)

			ginkgo.By("Sending pod-to-pod traffic to the other node")
			checker.ExpectSuccess(testClient, testServer.ClusterIPs()...)
			checker.Execute()

			Eventually(bytesSent).WithTimeout(90*time.Second).WithPolling(5*time.Second).
				Should(BeNumerically(">", before),
					"WireGuard byte counter on node %s did not advance, so the tunnel is not carrying traffic", clientNode)
		})
	})

func nodeInternalIP(f *framework.Framework, nodeName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	node, err := f.ClientSet.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "Error querying node %s", nodeName)

	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	framework.Failf("Node %s reports no internal IP", nodeName)
	return ""
}
