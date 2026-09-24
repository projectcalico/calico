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

package calico

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

const (
	whiskerGatewayName     = "calico-whisker-gateway"
	whiskerHTTPRouteName   = "calico-whisker-route"
	whiskerGatewayTLSName  = "calico-whisker-gateway-tls"
	whiskerBackendNS       = "calico-system"
	whiskerGatewayHostname = "whisker.e2e-test.local"

	// whiskerPageMarker is the Whisker UI's document title. Envoy's error pages do
	// not carry it, so it separates reaching Whisker from reaching the proxy.
	whiskerPageMarker = "<title>Calico Whisker"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IngressGateway"),
	describe.WithCategory(describe.Operator),
	describe.WithSerial(),
	describe.RequiresOperator(),
	describe.RequiresGoldmane(),
	"whisker access via calico ingress gateway",
	func() {
		f := utils.NewDefaultFramework("ingress-gateway-whisker")

		var (
			cli ctrlclient.Client
			ctx context.Context
		)

		ginkgo.BeforeEach(func() {
			ctx = context.Background()

			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(operatorv1.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(gatewayv1.Install(scheme)).NotTo(HaveOccurred())

			var err error
			cli, err = ctrlclient.NewWithWatch(f.ClientConfig(), ctrlclient.Options{Scheme: scheme})
			Expect(err).NotTo(HaveOccurred())
		})

		expectGone := func(get func(context.Context) error, what string) {
			Eventually(func() error {
				err := get(context.Background())
				if err == nil {
					return fmt.Errorf("%s still exists", what)
				}
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}, 2*time.Minute, 5*time.Second).Should(Succeed(), "%s should be deleted", what)
		}

		ginkgo.Context("Whisker accessible through Gateway in the install namespace", ginkgo.Ordered, func() {
			ginkgo.BeforeAll(func() {
				ginkgo.By("Enabling Gateway API support")
				// The GatewayAPI singleton must be "default" on OSS; the Enterprise
				// "tigera-secure" name makes the operator reject a second CR.
				restoreGatewayAPI, err := utils.ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &operatorv1.GatewayAPI{}, func(*operatorv1.GatewayAPI) {})
				Expect(err).NotTo(HaveOccurred(), "enabling the GatewayAPI CR")
				ginkgo.DeferCleanup(restoreGatewayAPI)

				ginkgo.By("Setting spec.ingressGateway on the Whisker CR")
				restoreWhisker, err := utils.ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &operatorv1.Whisker{}, func(w *operatorv1.Whisker) {
					w.Spec.IngressGateway = &operatorv1.IngressGatewaySpec{Hostname: whiskerGatewayHostname}
				})
				Expect(err).NotTo(HaveOccurred(), "setting spec.ingressGateway on the Whisker CR")
				ginkgo.DeferCleanup(restoreWhisker)

				ginkgo.By("Waiting for the Gateway to be accepted")
				// Accepted needs no cloud LoadBalancer, unlike Programmed; the wait also
				// covers the operator installing Envoy Gateway on the first GatewayAPI CR.
				Eventually(func() error {
					gw := &gatewayv1.Gateway{}
					if err := cli.Get(ctx, types.NamespacedName{Name: whiskerGatewayName, Namespace: whiskerBackendNS}, gw); err != nil {
						return err
					}
					for _, cond := range gw.Status.Conditions {
						if cond.Type == string(gatewayv1.GatewayConditionAccepted) && cond.Status == metav1.ConditionTrue {
							return nil
						}
					}
					return fmt.Errorf("Gateway %s/%s not Accepted yet", whiskerBackendNS, whiskerGatewayName)
				}, 5*time.Minute, 5*time.Second).Should(Succeed(), "Gateway should become Accepted")
			})

			ginkgo.It("should serve the Whisker UI through the Gateway", func() {
				ginkgo.By("Port-forwarding to the Gateway's Envoy proxy Service")
				kc := &utils.Kubectl{}
				stopCh := make(chan time.Time, 1)
				localPort, err := kc.PortForward(whiskerBackendNS, "svc/"+whiskerGatewayName, "443", "", stopCh)
				Expect(err).NotTo(HaveOccurred(), "port-forwarding to the Gateway proxy Service")
				ginkgo.DeferCleanup(func() { stopCh <- time.Now(); close(stopCh) })

				gw, err := utils.NewGatewayClient(ctx, cli, whiskerBackendNS, whiskerGatewayHostname)
				Expect(err).NotTo(HaveOccurred(), "building the gateway client")
				baseURL := fmt.Sprintf("https://127.0.0.1:%d", localPort)
				kc.WaitForPortForward(gw.HTTPClient(), baseURL+"/")

				ginkgo.By("Requesting the Whisker UI through the Gateway")
				// Envoy's default handler answers unrouted requests, so require the UI's
				// own 200 with its document title.
				Eventually(func() error {
					body, code, err := gw.Get(baseURL + "/")
					if err != nil {
						return err
					}
					if code != 200 {
						return fmt.Errorf("got status %d, want 200", code)
					}
					if !strings.Contains(body, whiskerPageMarker) {
						return fmt.Errorf("response did not contain %q; reached the proxy but not Whisker", whiskerPageMarker)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(), "the Whisker UI should be served through the Gateway")

				ginkgo.By("Querying flows through the Gateway")
				// A flow query crosses the one hop the UI shell does not: nginx proxying
				// over TLS to whisker-backend.
				Eventually(func() error {
					body, code, err := gw.Get(baseURL + "/whisker-backend/flows")
					if err != nil {
						return err
					}
					if code != 200 {
						return fmt.Errorf("got status %d, want 200: %.200s", code, body)
					}
					var flows map[string]json.RawMessage
					if err := json.Unmarshal([]byte(body), &flows); err != nil {
						return fmt.Errorf("response is not JSON; reached nginx but not whisker-backend: %.200s", body)
					}
					if _, ok := flows["items"]; !ok {
						return fmt.Errorf("JSON response has no items key; not a flows list: %.200s", body)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(), "flows should be served through the Gateway via nginx and whisker-backend")
			})

			ginkgo.It("should clean up gateway resources when spec.ingressGateway is removed", func() {
				ginkgo.By("Removing spec.ingressGateway from the Whisker CR")
				whisker := &operatorv1.Whisker{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, whisker)).NotTo(HaveOccurred())
				whisker.Spec.IngressGateway = nil
				Expect(cli.Update(ctx, whisker)).NotTo(HaveOccurred(), "removing spec.ingressGateway from the Whisker CR")

				expectGone(func(ctx context.Context) error {
					return cli.Get(ctx, types.NamespacedName{Name: whiskerGatewayName, Namespace: whiskerBackendNS}, &gatewayv1.Gateway{})
				}, "Gateway")
				expectGone(func(ctx context.Context) error {
					return cli.Get(ctx, types.NamespacedName{Name: whiskerHTTPRouteName, Namespace: whiskerBackendNS}, &gatewayv1.HTTPRoute{})
				}, "HTTPRoute")
				expectGone(func(ctx context.Context) error {
					return cli.Get(ctx, types.NamespacedName{Name: whiskerGatewayTLSName, Namespace: whiskerBackendNS}, &corev1.Secret{})
				}, "TLS Secret")
			})
		})
	},
)
