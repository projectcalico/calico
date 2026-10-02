// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
package policy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

// DESCRIPTION: This test verifies the staged network policy feature.
//
// DOCS_URL: https://docs.tigera.io/calico/latest/reference/resources/stagednetworkpolicy
// PRECONDITIONS:
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Flow-Logs"),
	describe.RequiresGoldmane(),
	describe.WithNoTierPrefix(),
	"staged network policy",
	func() {
		var (
			kubectl    *utils.Kubectl
			cli        ctrlclient.Client
			err        error
			customTier string

			f = utils.NewDefaultFramework("staged-policy")

			serverPodNamePrefix = "server-pod"
			clientPodNamePrefix = "client-pod"
			serverPort          = 80

			checker conncheck.ConnectionTester
		)

		BeforeEach(func() {
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())
			checker = conncheck.NewConnectionTester(f)

			installed, err := utils.WhiskerInstalled(cli)
			Expect(err).NotTo(HaveOccurred())
			if !installed {
				framework.Failf("Whisker is not installed in this cluster, so the lane should exclude the RequiresGoldmane label")
			}

			whiskerHTTPSClient, err = buildWhiskerHTTPSClient(context.TODO(), cli)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("Test presence in flow logs", func() {
			var (
				tierObj *v3.Tier
				client1 conncheck.Client
				server  conncheck.Server

				stopCh chan time.Time
				url    string
			)

			BeforeEach(func() {
				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())

				client1 = conncheck.NewClient(clientPodNamePrefix, f.Namespace)
				server = conncheck.NewServer(utils.GenerateRandomName(serverPodNamePrefix), f.Namespace)
				checker.AddClient(client1)
				checker.AddServer(server)
				checker.Deploy()

				// stopCh for kubectl
				stopCh = make(chan time.Time, 1)

				// We read flow logs from whisker-backend, we start port forward so we can query the flows
				localPort, err := kubectl.PortForward("calico-system", "deployment/whisker", "3002", "", stopCh)
				Expect(err).NotTo(HaveOccurred())

				// Build url to get flows from whisker
				url = buildURL(localPort, server.Pod().Namespace, server.Pod().Namespace, "-1800")

				// Port forward should be working and whisker-backend should return 200 status
				verifyPortForward(url)
			})

			AfterEach(func() {
				Expect(cli.Delete(context.TODO(), tierObj)).ShouldNot(HaveOccurred())

				checker.Stop()

				// Stop the kubectl port forward
				stopCh <- time.Now()
				close(stopCh)
			})

			Context("StagedKubernetesNetworkPolicy", func() {
				var stagedKubernetesNetworkPolicy *v3.StagedKubernetesNetworkPolicy
				BeforeEach(func() {
					// create policy
					podSelector := metav1.LabelSelector{MatchLabels: map[string]string{"pod-name": server.Name()}}
					stagedKubernetesNetworkPolicy = CreateStagedKubernetesNetworkPolicyIngressDeny("sknp-deny", server.Pod().Namespace, podSelector)

					Expect(cli.Create(context.TODO(), stagedKubernetesNetworkPolicy)).ShouldNot(HaveOccurred())

					// create client pod and connect from client to server
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				framework.ConformanceIt("Validate name, tier, action", func() {
					expectFlowWithStagedPolicy(url, checker, client1, server.ClusterIP().Port(serverPort), stagedPolicyHit{
						name: stagedKubernetesNetworkPolicy.Name,
						tier: "default",
						kind: whiskerv1.PolicyKindStagedKubernetesNetworkPolicy,

						// Action is empty for StagedKubernetesNetworkPolicy.
						action: whiskerv1.Action(0),
					})
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), stagedKubernetesNetworkPolicy)).ShouldNot(HaveOccurred())
				})
			})

			Context("StagedNetworkPolicy", func() {
				var (
					stagedPolicyName string
					stagedPolicy     *v3.StagedNetworkPolicy
				)

				BeforeEach(func() {
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())

					ingress := []v3.Rule{{Action: v3.Deny}}
					stagedPolicyName = "snp-deny-1"
					stagedPolicy = CreateStagedNetworkPolicy(stagedPolicyName, customTier, server.Pod().Namespace, 10, selector, ingress, nil)

					Expect(cli.Create(context.TODO(), stagedPolicy)).ShouldNot(HaveOccurred())

					// Connect to the server's cluster IPs.
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				framework.ConformanceIt("Validate name, tier, action", func() {
					expectFlowWithStagedPolicy(url, checker, client1, server.ClusterIP().Port(serverPort), stagedPolicyHit{
						name:   stagedPolicyName,
						tier:   stagedPolicy.Spec.Tier,
						kind:   whiskerv1.PolicyKindStagedNetworkPolicy,
						action: whiskerv1.ActionDeny,
					})
				})

				AfterEach(func() {
					// clean-up policy
					Expect(cli.Delete(context.TODO(), stagedPolicy)).ShouldNot(HaveOccurred())
				})
			})

			Context("StagedGlobalNetworkPolicy", func() {
				var (
					stagedGlobalNetworkPolicyName string
					stagedGlobalNetworkPolicy     *v3.StagedGlobalNetworkPolicy
				)

				BeforeEach(func() {
					selector := fmt.Sprintf("pod-name == \"%s\"", server.Name())
					ingress := []v3.Rule{{Action: v3.Deny}}
					stagedGlobalNetworkPolicyName = utils.GenerateRandomName("sgnp-deny")
					stagedGlobalNetworkPolicy = CreateStagedGlobalNetworkPolicy(stagedGlobalNetworkPolicyName, customTier, 10, selector, ingress, nil)

					Expect(cli.Create(context.TODO(), stagedGlobalNetworkPolicy)).ShouldNot(HaveOccurred())

					// create client pod and connect from client to server
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				framework.ConformanceIt("Validate name, tier, action", func() {
					expectFlowWithStagedPolicy(url, checker, client1, server.ClusterIP().Port(serverPort), stagedPolicyHit{
						name:   stagedGlobalNetworkPolicyName,
						tier:   stagedGlobalNetworkPolicy.Spec.Tier,
						kind:   whiskerv1.PolicyKindStagedGlobalNetworkPolicy,
						action: whiskerv1.ActionDeny,
					})
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), stagedGlobalNetworkPolicy)).ShouldNot(HaveOccurred())
				})
			})
		})

		Context("enforcing staged-policies", func() {
			var (
				tierObj *v3.Tier
				server  conncheck.Server
				client1 conncheck.Client
			)

			BeforeEach(func() {
				cli, err = client.New(f.ClientConfig())
				Expect(err).ToNot(HaveOccurred())

				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())
				DeferCleanup(func() {
					Eventually(func() error {
						return cli.Delete(context.TODO(), tierObj)
					}, 30*time.Second, 1*time.Second).Should(Succeed(), "Failed to delete tier %s", tierObj.Name)
				})

				// Create server
				server = conncheck.NewServer(utils.GenerateRandomName(serverPodNamePrefix), f.Namespace)
				client1 = conncheck.NewClient(clientPodNamePrefix, f.Namespace)
				checker.AddServer(server)
				checker.AddClient(client1)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()
			})

			Context("StagedKubernetesNetworkPolicy", func() {
				It("should enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					podSelector := metav1.LabelSelector{MatchLabels: server.Pod().Labels}
					policy := CreateStagedKubernetesNetworkPolicyIngressDeny("service-deny-in", server.Pod().Namespace, podSelector)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					})

					// enforce the policy
					_, enforced := ConvertStagedKubernetesPolicyToK8SEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					})

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})
			})

			Context("StagedNetworkPolicy", func() {
				It("should enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					ingress := []v3.Rule{{Action: v3.Deny}}
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())
					order := 200.0
					policy := CreateStagedNetworkPolicy("service-deny-in", customTier, server.Pod().Namespace, order, selector, ingress, nil)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					})

					// enforce the policy
					_, enforced := ConvertStagedPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					})

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})
			})

			Context("StagedGlobalNetworkPolicy", func() {
				It("should enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					ingress := []v3.Rule{{Action: v3.Deny}}
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())
					order := 200.0
					policyName := utils.GenerateRandomName("service-deny-in")
					policy := CreateStagedGlobalNetworkPolicy(policyName, customTier, order, selector, ingress, nil)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					})

					// enforce the policy
					_, enforced := ConvertStagedGlobalPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					DeferCleanup(func() {
						Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
					})

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})
			})
		})
	})

// whiskerHTTPSClient verifies whisker-backend's certificate against the
// cluster CA bundle. Populated once the bundle is read in BeforeEach.
var whiskerHTTPSClient *http.Client

// buildWhiskerHTTPSClient reads the cluster's CA bundle and returns a client
// that trusts certificates signed by it, such as whisker-backend's.
func buildWhiskerHTTPSClient(ctx context.Context, cli ctrlclient.Client) (*http.Client, error) {
	bundle := &corev1.ConfigMap{}
	err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: "calico-system", Name: "tigera-ca-bundle"}, bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to read tigera-ca-bundle: %w", err)
	}

	rootCAs := x509.NewCertPool()
	appended := false
	for _, pem := range bundle.Data {
		if rootCAs.AppendCertsFromPEM([]byte(pem)) {
			appended = true
		}
	}
	if !appended {
		return nil, fmt.Errorf("no CA certificates found in tigera-ca-bundle")
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
		Timeout:   30 * time.Second,
	}, nil
}

// whiskerGet fetches a whisker-backend URL over HTTPS, verifying the
// backend's certificate against the cluster CA bundle.
func whiskerGet(baseURL string) (*http.Response, error) {
	return whiskerHTTPSClient.Get("https://" + baseURL)
}

func buildURL(port int, sourceNamespace, destinationNamespace, startTime string) string {
	baseURL := fmt.Sprintf("localhost:%d/flows", port)

	f := whiskerv1.Filters{
		SourceNamespaces: whiskerv1.FilterMatches[string]{
			{Type: whiskerv1.MatchTypeExact, V: sourceNamespace},
		},
		DestNamespaces: whiskerv1.FilterMatches[string]{
			{Type: whiskerv1.MatchTypeExact, V: destinationNamespace},
		},
	}
	filtersJSON, err := json.Marshal(f)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	// Build query parameters for the URL.
	params := url.Values{}
	params.Add("filters", string(filtersJSON))
	params.Add("startTimeGte", startTime)
	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func verifyPortForward(url string) {
	// Port forward should be working and whisker-backend should return 200 status
	Eventually(func() error {
		resp, err := whiskerGet(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("http response is not successful %d, body: %s", resp.StatusCode, string(body))
		}

		return nil
	}, 30*time.Second, 1*time.Second).Should(Not(HaveOccurred()))
}

func getWhiskerFlows(url string) ([]whiskerv1.FlowResponse, error) {
	resp, err := whiskerGet(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d, body: %s", resp.StatusCode, string(body))
	}

	var response apiutil.List[whiskerv1.FlowResponse]
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	return response.Items, nil
}

// stagedPolicyHit is the pending policy a flow is expected to report.
type stagedPolicyHit struct {
	name   string
	tier   string
	kind   whiskerv1.PolicyKind
	action whiskerv1.Action
}

func (h stagedPolicyHit) matches(p *whiskerv1.PolicyHit) bool {
	return p != nil && p.Name == h.name && p.Tier == h.tier && p.Kind == h.kind && p.Action == h.action
}

// expectFlowWithStagedPolicy re-probes while polling, since Felix only evaluates pending policy for connections it still tracks.
func expectFlowWithStagedPolicy(url string, checker conncheck.ConnectionTester, cl conncheck.Client, target conncheck.Target, want stagedPolicyHit) {
	EventuallyWithOffset(1, func() error {
		if _, err := checker.Connect(cl, target); err != nil {
			logrus.WithError(err).Warnf("Probe from %s to %s failed, checking flows anyway", cl.Name(), target.String())
		}

		flows, err := getWhiskerFlows(url)
		if err != nil {
			return err
		}

		for _, flow := range flows {
			for _, pending := range flow.Policies.Pending {
				if pending == nil {
					continue
				}
				if want.matches(pending) || want.matches(pending.Trigger) {
					return nil
				}
			}
		}
		return fmt.Errorf(
			"no flow reports staged policy as pending: Kind:%s Name:%s Tier:%s Action:%s\n%s",
			want.kind, want.name, want.tier, want.action, formatFlowDiagnostics(flows),
		)
	}, 150*time.Second, 5*time.Second).Should(Succeed(), "timed out waiting for a flow reporting staged policy %s", want.name)
}

func formatFlowDiagnostics(flows []whiskerv1.FlowResponse) string {
	var diag strings.Builder
	diag.WriteString(fmt.Sprintf("Found %d flow(s):\n", len(flows)))
	for i, item := range flows {
		diag.WriteString(fmt.Sprintf(
			"  flow[%d]: reporter=%s action=%s src=%s/%s dst=%s/%s proto=%s destPort=%d\n",
			i, item.Reporter, item.Action,
			item.SourceNamespace, item.SourceName,
			item.DestNamespace, item.DestName,
			item.Protocol, item.DestPort,
		))
		if len(item.Policies.Enforced) > 0 {
			diag.WriteString("      enforced:\n")
			for _, p := range item.Policies.Enforced {
				diag.WriteString(fmt.Sprintf("        - %s\n", formatPolicyHit(p)))
			}
		}
		if len(item.Policies.Pending) > 0 {
			diag.WriteString("      pending:\n")
			for _, p := range item.Policies.Pending {
				diag.WriteString(fmt.Sprintf("        - %s\n", formatPolicyHit(p)))
				if p != nil && p.Trigger != nil {
					diag.WriteString(fmt.Sprintf("          triggered-by:\n            %s\n", formatPolicyHit(p.Trigger)))
				}
			}
		}
	}
	return diag.String()
}

func formatPolicyHit(p *whiskerv1.PolicyHit) string {
	if p == nil {
		return "<nil>"
	}
	msg := fmt.Sprintf("Kind:%s ", p.Kind)
	if p.Namespace != "" {
		msg += fmt.Sprintf("Namespace:%s ", p.Namespace)
	}
	if p.Name != "" {
		msg += fmt.Sprintf("Name:%s ", p.Name)
	}
	if p.Tier != "" {
		msg += fmt.Sprintf("Tier:%s ", p.Tier)
	}
	msg += fmt.Sprintf("Action:%s", p.Action)
	return msg
}

func CreateStagedNetworkPolicy(
	policyName, tier, namespace string,
	order float64,
	selector string,
	ingressRules, egressRules []v3.Rule,
) *v3.StagedNetworkPolicy {
	policy := v3.NewStagedNetworkPolicy()
	policy.ObjectMeta = metav1.ObjectMeta{Name: policyName, Namespace: namespace}

	var types []v3.PolicyType
	if len(ingressRules) > 0 {
		types = append(types, v3.PolicyTypeIngress)
	}
	if len(egressRules) > 0 {
		types = append(types, v3.PolicyTypeEgress)
	}

	policy.Spec = v3.StagedNetworkPolicySpec{
		Tier:     tier,
		Order:    &order,
		Ingress:  ingressRules,
		Egress:   egressRules,
		Selector: selector,
		Types:    types,
	}
	return policy
}

// CreateStagedKubernetesNetworkPolicyIngressDeny does not have an explicit Action: passing in an empty
// ingress and engress behaves as DENY for the traffic selected by the PodSelector.
func CreateStagedKubernetesNetworkPolicyIngressDeny(
	policyName, namespace string,
	podSelector metav1.LabelSelector,
) *v3.StagedKubernetesNetworkPolicy {
	policy := v3.NewStagedKubernetesNetworkPolicy()
	policy.ObjectMeta = metav1.ObjectMeta{
		Name:      policyName,
		Namespace: namespace,
	}
	policy.Spec = v3.StagedKubernetesNetworkPolicySpec{
		PodSelector: podSelector,
		Ingress:     []networkingv1.NetworkPolicyIngressRule{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	}
	return policy
}

func CreateStagedGlobalNetworkPolicy(
	policyName, tier string,
	order float64,
	selector string,
	ingressRules, egressRules []v3.Rule,
) *v3.StagedGlobalNetworkPolicy {
	policy := v3.NewStagedGlobalNetworkPolicy()
	policy.ObjectMeta = metav1.ObjectMeta{Name: policyName}

	var types []v3.PolicyType
	if len(ingressRules) > 0 {
		types = append(types, v3.PolicyTypeIngress)
	}
	if len(egressRules) > 0 {
		types = append(types, v3.PolicyTypeEgress)
	}

	policy.Spec = v3.StagedGlobalNetworkPolicySpec{
		Order:    &order,
		Tier:     tier,
		Selector: selector,
		Ingress:  ingressRules,
		Egress:   egressRules,
		Types:    types,
	}
	return policy
}
