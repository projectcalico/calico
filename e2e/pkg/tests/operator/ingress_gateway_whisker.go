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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"
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

	// The Whisker UI's document title. Envoy's own error pages do not carry it,
	// so it separates "reached Whisker" from "reached the proxy".
	whiskerPageMarker = "<title>Calico Whisker"

	// Bound every context so a hung API call fails the spec with a readable
	// error instead of running into Ginkgo's global timeout.
	whiskerSpecTimeout    = 10 * time.Minute
	whiskerCleanupTimeout = 2 * time.Minute

	// A delete poll runs on its own context, so it always gets the full window
	// however much of the cleanup budget the steps before it used.
	whiskerGoneTimeout = 2 * time.Minute

	// gatewayAPICreatedByLabel marks a GatewayAPI CR this suite created, so
	// cleanup only removes its own and never a CR the cluster came with.
	gatewayAPICreatedByLabel = "e2e.tigera.io/created-by"
	gatewayAPICreatedByValue = "ingress-gateway-whisker-e2e"
)

// This test validates Whisker access via Calico Ingress Gateway: the full
// lifecycle wired end to end — Whisker CR patch, operator render, Envoy proxy
// serving the Whisker UI, and teardown. That is the one thing that needs a real
// cluster; everything else lives at a lower test level: rendered object shapes,
// the degrade cases, and the per-namespace RBAC the GatewayAPI controller
// provisions are all covered by operator unit and FV tests.
//
// Unlike the Manager gateway, Whisker's gateway defaults to the namespace its
// backing Service already lives in, so this exercises the same-namespace render
// including the proxy NetworkPolicy.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Ingress-Gateway"),
	describe.WithCategory(describe.Operator),
	// Patches the cluster-singleton Whisker and GatewayAPI CRs, so it must not
	// run alongside other specs.
	describe.WithSerial(),
	describe.RequiresGoldmane(),
	"whisker access via calico ingress gateway",
	func() {
		f := utils.NewDefaultFramework("ingress-gateway-whisker")

		var (
			cli ctrlclient.Client
			ctx context.Context
		)

		ginkgo.BeforeEach(func() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), whiskerSpecTimeout)
			ginkgo.DeferCleanup(cancel)

			scheme := runtime.NewScheme()
			Expect(operatorv1.AddToScheme(scheme)).NotTo(HaveOccurred(), "registering operator.tigera.io/v1")
			Expect(gatewayv1.Install(scheme)).NotTo(HaveOccurred(), "registering gateway.networking.k8s.io/v1")

			var err error
			cli, err = ctrlclient.NewWithWatch(f.ClientConfig(), ctrlclient.Options{Scheme: scheme})
			Expect(err).NotTo(HaveOccurred(), "creating a controller-runtime client")

			// Skip rather than fail on a cluster this feature cannot run on: it
			// needs an operator-managed Calico install with Whisker present.
			installation := &operatorv1.Installation{}
			if err := cli.Get(ctx, types.NamespacedName{Name: "default"}, installation); apierrors.IsNotFound(err) {
				ginkgo.Skip("No Installation; this cluster is not operator managed")
			} else {
				Expect(err).NotTo(HaveOccurred(), "reading the Installation")
			}
			if installation.Spec.Variant != operatorv1.Calico {
				ginkgo.Skip("Whisker only runs on the Calico variant")
			}
			if err := cli.Get(ctx, types.NamespacedName{Name: "default"}, &operatorv1.Whisker{}); apierrors.IsNotFound(err) {
				ginkgo.Skip("No Whisker CR on this cluster")
			} else {
				Expect(err).NotTo(HaveOccurred(), "reading the Whisker CR")
			}
		})

		// expectGone polls until get returns NotFound. Any other error (or the
		// object still existing) keeps the poll going and is reported on
		// timeout instead of a bare "expected false to be true".
		//
		// The poll gets a fresh context rather than the caller's: a cleanup
		// context part-spent on earlier steps would expire mid-poll, and every
		// remaining attempt would then fail on the dead context instead of
		// reporting what was still there.
		expectGone := func(get func(context.Context) error, what string) {
			pollCtx, cancel := context.WithTimeout(context.Background(), whiskerGoneTimeout+30*time.Second)
			defer cancel()
			Eventually(func() error {
				err := get(pollCtx)
				if err == nil {
					return fmt.Errorf("%s still exists", what)
				}
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}, whiskerGoneTimeout, 5*time.Second).Should(Succeed(), "%s should be deleted", what)
		}

		ginkgo.Context("Whisker accessible through Gateway in the install namespace", ginkgo.Ordered, func() {
			ginkgo.BeforeAll(func() {
				ctx, cancel := context.WithTimeout(context.Background(), whiskerSpecTimeout)
				ginkgo.DeferCleanup(cancel)

				ginkgo.By("Enabling Gateway API support")
				createWhiskerGatewayAPICR(ctx, cli)

				ginkgo.By("Setting spec.ingressGateway on the Whisker CR")
				whisker := &operatorv1.Whisker{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, whisker)).NotTo(HaveOccurred(), "reading the Whisker CR")
				patch := fmt.Sprintf(`{"spec":{"ingressGateway":{"hostname":%q}}}`, whiskerGatewayHostname)
				Expect(cli.Patch(ctx, whisker, ctrlclient.RawPatch(types.MergePatchType, []byte(patch)))).NotTo(HaveOccurred(),
					"setting spec.ingressGateway on the Whisker CR")

				ginkgo.DeferCleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), whiskerCleanupTimeout)
					defer cancel()

					ginkgo.By("Removing spec.ingressGateway from the Whisker CR")
					w := &operatorv1.Whisker{}
					if err := cli.Get(cleanupCtx, types.NamespacedName{Name: "default"}, w); err != nil {
						logrus.WithError(err).Warn("Failed to get Whisker CR for cleanup")
						return
					}
					removePatch := []byte(`{"spec":{"ingressGateway":null}}`)
					if err := cli.Patch(cleanupCtx, w, ctrlclient.RawPatch(types.MergePatchType, removePatch)); err != nil {
						logrus.WithError(err).Warn("Failed to remove spec.ingressGateway from the Whisker CR")
					}

					// Wait the Gateway out before dropping the GatewayAPI CR.
					// Envoy Gateway holds a finalizer on the GatewayClass while
					// any Gateway still references it, so tearing the controller
					// down first leaves nothing to clear it and the GatewayClass
					// and its namespace hang in Terminating.
					ginkgo.By("Waiting for gateway resources to be cleaned up")
					expectGone(func(ctx context.Context) error {
						return cli.Get(ctx, types.NamespacedName{Name: whiskerGatewayName, Namespace: whiskerBackendNS}, &gatewayv1.Gateway{})
					}, "Gateway")

					ginkgo.By("Deleting the GatewayAPI CR")
					deleteWhiskerGatewayAPICR(cleanupCtx, cli)
				})

				ginkgo.By("Waiting for the Gateway to be accepted")
				// Accepted is set by the Gateway API controller without needing
				// a cloud LoadBalancer; Programmed never goes True without an
				// assigned address, so it is deliberately not waited on here.
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
				}, 3*time.Minute, 5*time.Second).Should(Succeed(), "Gateway should become Accepted")
			})

			ginkgo.It("should serve the Whisker UI through the Gateway", func() {
				ctx, cancel := context.WithTimeout(context.Background(), whiskerSpecTimeout)
				ginkgo.DeferCleanup(cancel)

				ginkgo.By("Port-forwarding to the Gateway's Envoy proxy Service")
				baseURL, stop := utils.GatewayProxyBaseURL(ctx, f.ClientSet, whiskerBackendNS, whiskerGatewayName, true)
				ginkgo.DeferCleanup(stop)

				ginkgo.By("Requesting the Whisker UI through the Gateway")
				gwClient := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs: whiskerCABundle(ctx, f),
							// SNI must match the Gateway listener hostname or
							// Envoy has no filter chain for the connection.
							ServerName: whiskerGatewayHostname,
						},
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
					Timeout: 10 * time.Second,
				}

				// Envoy's default handler answers unrouted requests, so a
				// response alone proves nothing: require the Whisker UI's own
				// 200 with its document title.
				Eventually(func() error {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
					if err != nil {
						return err
					}
					req.Host = whiskerGatewayHostname

					resp, err := gwClient.Do(req)
					if err != nil {
						return err
					}
					defer resp.Body.Close()

					body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
					if err != nil {
						return err
					}
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("got status %d, want 200", resp.StatusCode)
					}
					if !strings.Contains(string(body), whiskerPageMarker) {
						return fmt.Errorf("response did not contain %q; reached the proxy but not Whisker", whiskerPageMarker)
					}
					return nil
				}, 3*time.Minute, 5*time.Second).Should(Succeed(), "the Whisker UI should be served through the Gateway")

				// The UI shell above is served by nginx alone. A flow query
				// crosses the one hop nothing else tests end to end: nginx
				// proxying over TLS to whisker-backend inside the pod.
				ginkgo.By("Querying flows through the Gateway")
				Eventually(func() error {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/whisker-backend/flows", nil)
					if err != nil {
						return err
					}
					req.Host = whiskerGatewayHostname

					resp, err := gwClient.Do(req)
					if err != nil {
						return err
					}
					defer resp.Body.Close()

					body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					if err != nil {
						return err
					}
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("got status %d, want 200: %.200s", resp.StatusCode, body)
					}
					// nginx rewrites errors to HTML pages, so require the
					// backend's JSON list shape, not just a 200.
					var flows map[string]json.RawMessage
					if err := json.Unmarshal(body, &flows); err != nil {
						return fmt.Errorf("response is not JSON; reached nginx but not whisker-backend: %.200s", body)
					}
					if _, ok := flows["items"]; !ok {
						return fmt.Errorf("JSON response has no items key; not a flows list: %.200s", body)
					}
					return nil
				}, 3*time.Minute, 5*time.Second).Should(Succeed(), "flows should be served through the Gateway via nginx and whisker-backend")
			})

			ginkgo.It("should clean up gateway resources when spec.ingressGateway is removed", func() {
				ctx, cancel := context.WithTimeout(context.Background(), whiskerSpecTimeout)
				ginkgo.DeferCleanup(cancel)

				ginkgo.By("Removing spec.ingressGateway from the Whisker CR")
				whisker := &operatorv1.Whisker{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, whisker)).NotTo(HaveOccurred(), "reading the Whisker CR")
				removePatch := []byte(`{"spec":{"ingressGateway":null}}`)
				Expect(cli.Patch(ctx, whisker, ctrlclient.RawPatch(types.MergePatchType, removePatch))).NotTo(HaveOccurred(),
					"removing spec.ingressGateway from the Whisker CR")

				expectGone(func(ctx context.Context) error {
					return cli.Get(ctx, types.NamespacedName{Name: whiskerGatewayName, Namespace: whiskerBackendNS}, &gatewayv1.Gateway{})
				}, "Gateway")
				expectGone(func(ctx context.Context) error {
					return cli.Get(ctx, types.NamespacedName{Name: whiskerHTTPRouteName, Namespace: whiskerBackendNS}, &gatewayv1.HTTPRoute{})
				}, "HTTPRoute")
				expectGone(func(ctx context.Context) error {
					_, err := f.ClientSet.CoreV1().Secrets(whiskerBackendNS).Get(ctx, whiskerGatewayTLSName, metav1.GetOptions{})
					return err
				}, "TLS Secret")
			})
		})
	},
)

// createWhiskerGatewayAPICR enables Gateway API support, waiting out any
// deletion still in progress from a previous run's cleanup. The CR is stamped
// so cleanup can tell it apart from one the cluster already had.
func createWhiskerGatewayAPICR(ctx context.Context, cli ctrlclient.Client) {
	Eventually(func() error {
		gatewayAPI := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "tigera-secure",
				Labels: map[string]string{gatewayAPICreatedByLabel: gatewayAPICreatedByValue},
			},
		}
		err := cli.Create(ctx, gatewayAPI)
		if err == nil || apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}, 2*time.Minute, 5*time.Second).Should(Succeed(), "the GatewayAPI CR should be created")
}

// deleteWhiskerGatewayAPICR deletes the GatewayAPI CR, but only when this suite
// created it: deleting one the cluster already had takes envoy-gateway down
// with it and breaks every later suite.
func deleteWhiskerGatewayAPICR(ctx context.Context, cli ctrlclient.Client) {
	existing := &operatorv1.GatewayAPI{}
	if err := cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			logrus.WithError(err).Warn("Failed to read GatewayAPI CR for cleanup")
		}
		return
	}
	if existing.Labels[gatewayAPICreatedByLabel] != gatewayAPICreatedByValue {
		logrus.Info("Leaving pre-existing GatewayAPI CR in place")
		return
	}
	if err := cli.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
		logrus.WithError(err).Warn("Failed to delete GatewayAPI CR")
	}
}

// whiskerCABundle returns the cluster's CA bundle, which signs the Gateway
// listener certificate the operator renders.
func whiskerCABundle(ctx context.Context, f *framework.Framework) *x509.CertPool {
	cm, err := f.ClientSet.CoreV1().ConfigMaps(whiskerBackendNS).Get(ctx, "tigera-ca-bundle", metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "reading the tigera-ca-bundle ConfigMap")

	roots := x509.NewCertPool()
	caCert, ok := cm.Data["tigera-ca-bundle.crt"]
	Expect(ok).To(BeTrue(), "tigera-ca-bundle ConfigMap should hold tigera-ca-bundle.crt")
	Expect(roots.AppendCertsFromPEM([]byte(caCert))).To(BeTrue(), "the CA bundle should parse")
	return roots
}
