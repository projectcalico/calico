// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package policy

import (
	"context"
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

			// These tests rely on Whisker - if Whisker is not installed, short-circuit the tests.
			installed, err := utils.WhiskerInstalled(cli)
			Expect(err).NotTo(HaveOccurred())
			Expect(installed).To(BeTrue(), "Whisker is not installed in the cluster")
		})

		Context("Test presence in flow logs", func() {
			var (
				tierObj *v3.Tier
				client1 *conncheck.Client
				server  *conncheck.Server

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
				kubectl.PortForward("calico-system", "deployment/whisker", "3002", "", stopCh)

				// Build url to get flows from whisker
				url = buildURL(server.Pod().Namespace, server.Pod().Namespace, "-1800")

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
					verifyFlowCount(url, 2)
					verifyFlowContainsStagedPolicy(
						url,
						stagedKubernetesNetworkPolicy.Name,
						"default",
						whiskerv1.PolicyKindStagedKubernetesNetworkPolicy,
						whiskerv1.Action(0), // Action is empty for StagedKubernetesNetworkPolicy
					)
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
					verifyFlowCount(url, 2)

					verifyFlowContainsStagedPolicy(
						url,
						stagedPolicyName,
						stagedPolicy.Spec.Tier,
						whiskerv1.PolicyKindStagedNetworkPolicy,
						whiskerv1.ActionDeny,
					)
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
					stagedGlobalNetworkPolicyName = "sgnp-deny-1"
					stagedGlobalNetworkPolicy = CreateStagedGlobalNetworkPolicy(stagedGlobalNetworkPolicyName, customTier, 10, selector, ingress, nil)

					Expect(cli.Create(context.TODO(), stagedGlobalNetworkPolicy)).ShouldNot(HaveOccurred())

					// create client pod and connect from client to server
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				framework.ConformanceIt("Validate name, tier, action", func() {
					verifyFlowCount(url, 2)
					verifyFlowContainsStagedPolicy(
						url,
						stagedGlobalNetworkPolicyName,
						stagedGlobalNetworkPolicy.Spec.Tier,
						whiskerv1.PolicyKindStagedGlobalNetworkPolicy,
						whiskerv1.ActionDeny,
					)
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), stagedGlobalNetworkPolicy)).ShouldNot(HaveOccurred())
				})
			})
		})

		Context("enforcing staged-policies", func() {
			var (
				tierObj *v3.Tier
				server  *conncheck.Server
				client1 *conncheck.Client
			)

			BeforeEach(func() {
				cli, err = client.New(f.ClientConfig())
				Expect(err).ToNot(HaveOccurred())

				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())

				// Create server
				server = conncheck.NewServer(utils.GenerateRandomName(serverPodNamePrefix), f.Namespace)
				client1 = conncheck.NewClient(clientPodNamePrefix, f.Namespace)
				checker.AddServer(server)
				checker.AddClient(client1)
				checker.Deploy()
			})

			AfterEach(func() {
				Expect(cli.Delete(context.TODO(), tierObj)).ShouldNot(HaveOccurred())
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

					// enforce the policy
					_, enforced := ConvertStagedPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// delete policies
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
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
					policy := CreateStagedGlobalNetworkPolicy("service-deny-in", customTier, order, selector, ingress, nil)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())

					// enforce the policy
					_, enforced := ConvertStagedGlobalPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// delete policies
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
				})
			})
		})
	})

func buildURL(sourceNamespace, destinationNamespace, startTime string) string {
	baseURL := "http://localhost:3002/flows"

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
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("http response is not successful %d", resp.StatusCode)
		}

		return nil
	}, 30*time.Second, 1*time.Second).Should(Not(HaveOccurred()))
}

func verifyFlowCount(url string, count int) {
	var response apiutil.List[whiskerv1.FlowResponse]

	EventuallyWithOffset(1, func() error {
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(body, &response); err != nil {
			return err
		}

		if len(response.Items) != count {
			return fmt.Errorf("number of flow items does not match, expected %d, got %d", count, len(response.Items))
		}

		return nil
	}, 90*time.Second, 5*time.Second).Should(Not(HaveOccurred()))
}

func verifyFlowContainsStagedPolicy(url, name, tier string, kind whiskerv1.PolicyKind, action whiskerv1.Action) {
	var response apiutil.List[whiskerv1.FlowResponse]
	containsStagedPolicy := false

	resp, err := http.Get(url)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	err = json.Unmarshal(body, &response)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	ExpectWithOffset(1, kind).NotTo(Equal(""), "BUG: kind should not be empty")

	// Build up an error message to help debug if the policy is not found
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("Could not find flow:\nKind:%s Name:%s Tier:%s Action:%s\n\n", kind, name, tier, action))
	msg.WriteString(fmt.Sprintf("Found %d flow items:\n", len(response.Items)))

responseLoop:
	for _, item := range response.Items {
		pendingPolicies := item.Policies.Pending
		for _, pending := range pendingPolicies {
			msg.WriteString(fmt.Sprintf(
				"  - %s\n", policyHitString(
					pending.Kind,
					pending.Namespace,
					pending.Name,
					pending.Tier,
					pending.Action,
				)))

			if pending.Name == name &&
				pending.Tier == tier &&
				pending.Kind == kind &&
				pending.Action == action {
				containsStagedPolicy = true
				break responseLoop
			}

			if pending.Trigger != nil {
				msg.WriteString(fmt.Sprintf(
					"    - TriggeredBy(%s)\n",
					policyHitString(
						pending.Trigger.Kind,
						pending.Trigger.Namespace,
						pending.Trigger.Name,
						pending.Trigger.Tier,
						pending.Trigger.Action,
					)))
				if pending.Trigger.Name == name &&
					pending.Trigger.Tier == tier &&
					pending.Trigger.Kind == kind &&
					pending.Trigger.Action == action {
					containsStagedPolicy = true
					break responseLoop
				}
			}
		}
	}

	Expect(containsStagedPolicy).Should(BeTrue(), msg.String())
}

func policyHitString(kind whiskerv1.PolicyKind, namespace, name, tier string, action whiskerv1.Action) string {
	msg := fmt.Sprintf("Kind:%s ", kind)
	if namespace != "" {
		msg += fmt.Sprintf("Namespace:%s ", namespace)
	}
	if name != "" {
		msg += fmt.Sprintf("Name:%s ", name)
	}
	if tier != "" {
		msg += fmt.Sprintf("Tier:%s ", tier)
	}
	msg += fmt.Sprintf("Action:%s ", action)
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
