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

package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

const (
	// authzUnauthorizedTTL mirrors unauthorizedTTL in
	// webhooks/config/authorization-configuration.yaml. The API server caches Denied and
	// NoOpinion for this long, so a spec that changes a grant and expects the decision to
	// follow has to poll for longer than this rather than assert once.
	authzUnauthorizedTTL = 30 * time.Second

	// webhookAppLabel selects the authorization webhook's Deployment and pods. Matched by
	// label rather than by name and namespace because the chart installs it into kube-system
	// and the operator installs it into calico-system.
	webhookAppLabel = "k8s-app=calico-webhooks"

	// authzExemptServiceAccount is one of the identities the matchConditions in
	// webhooks/config/authorization-configuration.yaml exempt from the webhook. calico-node is
	// picked of the three because its own ClusterRole (charts/calico/templates/
	// calico-node-rbac.yaml) grants unrestricted get/list/watch on networkpolicies and none on
	// tier.networkpolicies, so a list by this identity is allowed by RBAC alone and would be
	// denied by the webhook. That makes it an unambiguous probe of the exemption.
	authzExemptServiceAccount = "system:serviceaccount:kube-system:calico-node"
)

// DESCRIPTION: Verify tiered RBAC on the read path (GET/LIST/WATCH). Two different components
// can enforce this: the aggregated Calico API server, or, in v3 CRD mode, the Calico
// authorization webhook in the kube-apiserver's authorization chain. The cases in this block
// hold identically under either, so they are gated on detecting one of them.
//
// PRECONDITIONS: Either the aggregated Calico API server or the Calico authorization webhook.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	describe.RequiresReadPathTierRBAC(),
	"Tiered RBAC on reads",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac-reads")

		var fx *tieredRBACFixture

		BeforeEach(func() {
			requireReadPathTierRBAC(f.ClientConfig())
			fx = setupTieredRBACFixture(f)
		})

		framework.ConformanceIt("should scope a GlobalNetworkPolicy list to the selected tier", func() {
			mine := fx.createGlobalNetworkPolicy("list-gnp-mine", fx.testTier)
			theirs := fx.createGlobalNetworkPolicy("list-gnp-theirs", fx.otherTier)

			cli := fx.impersonate(rbacListTierUser)

			By("Listing GlobalNetworkPolicies in the permitted tier")
			list := &v3.GlobalNetworkPolicyList{}
			Expect(cli.List(fx.ctx, list, ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier})).To(
				Succeed(), "a tier-scoped list should be allowed for a user authorized on that tier",
			)
			names := gnpNames(list)
			Expect(names).To(ContainElement(mine.Name), "expected the permitted tier's policy in the list")
			Expect(names).NotTo(ContainElement(theirs.Name), "the other tier's policy must not be visible")

			By("Listing GlobalNetworkPolicies in a tier the user is not authorized for")
			err := cli.List(fx.ctx, &v3.GlobalNetworkPolicyList{},
				ctrlclient.MatchingLabels{v3.LabelTier: fx.otherTier})
			Expect(err).To(HaveOccurred(), "a list selecting an unauthorized tier should be refused")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring(inTierMessage(fx.otherTier)),
				"the denial should name the tier the request selected")
		})

		framework.ConformanceIt("should scope a NetworkPolicy list to the selected tier", func() {
			mine := fx.createNetworkPolicy("list-np-mine", fx.testTier)
			theirs := fx.createNetworkPolicy("list-np-theirs", fx.otherTier)

			cli := fx.impersonate(rbacListTierUser)

			By("Listing NetworkPolicies in the permitted tier")
			list := &v3.NetworkPolicyList{}
			Expect(cli.List(fx.ctx, list,
				ctrlclient.InNamespace(f.Namespace.Name),
				ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier},
			)).To(Succeed(), "a tier-scoped list should be allowed for a user authorized on that tier")
			names := npNames(list)
			Expect(names).To(ContainElement(mine.Name), "expected the permitted tier's policy in the list")
			Expect(names).NotTo(ContainElement(theirs.Name), "the other tier's policy must not be visible")

			By("Listing NetworkPolicies in a tier the user is not authorized for")
			err := cli.List(fx.ctx, &v3.NetworkPolicyList{},
				ctrlclient.InNamespace(f.Namespace.Name),
				ctrlclient.MatchingLabels{v3.LabelTier: fx.otherTier},
			)
			Expect(err).To(HaveOccurred(), "a list selecting an unauthorized tier should be refused")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring(inTierMessage(fx.otherTier)),
				"the denial should name the tier the request selected")
		})

		// Tiered RBAC needs two grants: GET on the tier, and the verb on the tier-scoped
		// policy resource. This user has the second but not the first, which proves the tier
		// GET is load-bearing on reads and not only on writes.
		framework.ConformanceIt("should deny a tier-scoped list for a user without GET on the tier", func() {
			fx.createNetworkPolicy("list-no-tier-get", fx.testTier)

			cli := fx.impersonate(rbacListNoTierGetUser)

			err := cli.List(fx.ctx, &v3.NetworkPolicyList{},
				ctrlclient.InNamespace(f.Namespace.Name),
				ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier},
			)
			Expect(err).To(HaveOccurred(), "a list should be refused without GET on the tier")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring(inTierMessage(fx.testTier)),
				"the denial should name the tier the request selected")
			Expect(err.Error()).To(ContainSubstring(missingTierGetMessage),
				"the denial should say the missing grant is GET on the tier, not the policy verb")
		})
	},
)

// DESCRIPTION: Verify the behavior that is specific to the Calico authorization webhook, as
// opposed to the aggregated API server. The webhook refuses a read that spans every tier
// unless the user is unrestricted by tier, and it decides GET by resolving the policy's
// current tier, so moving a policy between tiers changes who may read it.
//
// PRECONDITIONS: The Calico authorization webhook in the kube-apiserver authorization chain.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	describe.RequiresAuthzWebhook(),
	"Tiered RBAC authorization webhook",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac-authz")

		var fx *tieredRBACFixture

		BeforeEach(func() {
			requireAuthzWebhook(f.ClientConfig())
			fx = setupTieredRBACFixture(f)
		})

		// An unselectored list has no tier to authorize against, so the only user who may
		// issue one is a user whose tier grants carry no resourceNames. The error names the
		// label to select on, because that is the one denial the user can act on.
		It("should deny an unselectored list for a tier-restricted user", func() {
			fx.createNetworkPolicy("unselectored-denied", fx.testTier)

			cli := fx.impersonate(rbacListRestrictedUser)

			err := cli.List(fx.ctx, &v3.NetworkPolicyList{}, ctrlclient.InNamespace(f.Namespace.Name))
			Expect(err).To(HaveOccurred(), "an unselectored list should be refused for a tier-restricted user")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring(v3.LabelTier),
				"the denial should tell the user which label to select on")
		})

		It("should allow an unselectored list for a user unrestricted by tier", func() {
			mine := fx.createNetworkPolicy("unselectored-allowed", fx.testTier)
			theirs := fx.createNetworkPolicy("unselectored-allowed-other", fx.otherTier)

			cli := fx.impersonate(rbacListAllTiersUser)

			list := &v3.NetworkPolicyList{}
			Expect(cli.List(fx.ctx, list, ctrlclient.InNamespace(f.Namespace.Name))).To(
				Succeed(), "an unselectored list should be allowed for a tier-unrestricted user",
			)
			names := npNames(list)
			Expect(names).To(ContainElement(mine.Name))
			Expect(names).To(ContainElement(theirs.Name), "a tier-unrestricted user should see every tier")
		})

		// The API server caches NoOpinion as well as Denied, so a grant added after a denial
		// only takes effect once that cache entry expires. Poll rather than sleep, but for
		// longer than the TTL.
		It("should honor a tier grant added after a denial", func() {
			fx.createNetworkPolicy("recovery", fx.testTier)

			cli := fx.impersonate(rbacListRecoveryUser)
			listInTier := func() error {
				return cli.List(fx.ctx, &v3.NetworkPolicyList{},
					ctrlclient.InNamespace(f.Namespace.Name),
					ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier},
				)
			}

			By("Confirming the user is denied while the tier GET grant is missing")
			err := listInTier()
			Expect(err).To(HaveOccurred(), "the user should start out denied")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)

			By("Granting GET on the tier")
			fx.grantTierGet("recovery-grant", rbacListRecoveryUser, fx.testTier)

			By("Waiting for the cached denial to expire")
			Eventually(listInTier, 4*authzUnauthorizedTTL, 2*time.Second).Should(
				Succeed(), "access should recover once the cached denial expires",
			)
		})

		// spec.tier is mutable, and the webhook resolves a named read's tier from the object
		// rather than from the request. A reader authorized only for the policy's original
		// tier must lose access when it moves. A stale cache entry here is a security bug, not
		// an annoyance, which is why this asserts the loss and not just the initial access.
		It("should revoke read access when a policy moves into a restricted tier", func() {
			np := fx.createNetworkPolicy("revoke", fx.otherTier)
			key := ctrlclient.ObjectKeyFromObject(np)

			cli := fx.impersonate(rbacListRevokeUser)
			get := func() error { return cli.Get(fx.ctx, key, v3.NewNetworkPolicy()) }

			By("Confirming the reader can get the policy in its original tier")
			Eventually(get, authzUnauthorizedTTL, 2*time.Second).Should(
				Succeed(), "the reader should be able to get a policy in the tier it is authorized for",
			)

			By("Moving the policy into a tier the reader is not authorized for")
			Expect(fx.adminCli.Get(fx.ctx, key, np)).To(Succeed())
			np.Spec.Tier = fx.testTier
			Expect(fx.adminCli.Update(fx.ctx, np)).To(Succeed(), "admin should be able to move the policy")

			By("Waiting for the reader to lose access")
			Eventually(func() error {
				err := get()
				switch {
				case err == nil:
					return fmt.Errorf("read is still permitted after the policy moved tier")
				case apierrors.IsForbidden(err):
					return nil
				default:
					return fmt.Errorf("expected forbidden, got: %w", err)
				}
			}, 4*authzUnauthorizedTTL, 2*time.Second).Should(
				Succeed(), "the reader should lose access within the decision cache TTL",
			)
		})
	},
)

// DESCRIPTION: Verify that a Calico authorization webhook outage fails closed for user reads
// while leaving Calico's own components working. The authorization configuration sets
// failurePolicy: Deny and exempts Calico's service accounts by CEL matchCondition, and this is
// the only test that exercises either.
//
// PRECONDITIONS: The Calico authorization webhook in the kube-apiserver authorization chain.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	describe.RequiresAuthzWebhook(),
	describe.WithSerial(),
	describe.WithDisruptive(),
	"Tiered RBAC authorization webhook outage",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac-authz-outage")

		var (
			fx      *tieredRBACFixture
			checker conncheck.ConnectionTester
			server  conncheck.Server
			cl      conncheck.Client
		)

		BeforeEach(func() {
			requireAuthzWebhook(f.ClientConfig())
			fx = setupTieredRBACFixture(f)

			// Deployed before the outage on purpose. Creating a pod while the webhook is down
			// makes the CNI plugin write IPAM resources in the projectcalico.org group as
			// calico-cni-plugin, which the exempt-identity list does not cover, so it would be
			// denied. This spec is about the components that are exempt.
			checker = conncheck.NewConnectionTester(f)
			server = conncheck.NewServer("server", f.Namespace)
			cl = conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(cl)
			checker.Deploy()
			DeferCleanup(func() { checker.Stop() })
		})

		It("should fail closed for reads while Calico keeps running", func() {
			fx.createNetworkPolicy("fail-closed", fx.testTier)

			cli := fx.impersonate(rbacFailClosedUser)
			listInTier := func() error {
				return cli.List(fx.ctx, &v3.NetworkPolicyList{},
					ctrlclient.InNamespace(f.Namespace.Name),
					ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier},
				)
			}

			By("Confirming the read is permitted while the webhook is up")
			Expect(listInTier()).To(Succeed(), "the read should be permitted before the outage")

			By("Scaling the webhook deployment to zero")
			fx.scaleWebhook(0)

			By("Verifying a tiered policy read now fails closed")
			Eventually(func() error {
				err := listInTier()
				switch {
				case err == nil:
					return fmt.Errorf("read is still permitted with the webhook scaled to zero")
				case apierrors.IsForbidden(err):
					return nil
				default:
					// A connection-level error from the API server is not fail-closed
					// behavior; report it rather than treating it as success.
					return fmt.Errorf("expected forbidden, got: %w", err)
				}
			}, 2*time.Minute, 2*time.Second).Should(Succeed(), "reads should be denied while the webhook is down")

			By("Verifying an exempt Calico service account can still read policies")
			// The direct assertion on the service-account exemption, and the counterpart to the
			// denial above. failurePolicy: Deny refuses every projectcalico.org request that
			// reaches the webhook while it is down, so a read that succeeds proves the
			// matchCondition skipped the webhook and left the decision to RBAC.
			exempt := fx.impersonate(authzExemptServiceAccount)
			exemptErr := exempt.List(fx.ctx, &v3.NetworkPolicyList{}, ctrlclient.InNamespace(f.Namespace.Name))
			if exemptErr != nil && strings.Contains(exemptErr.Error(), "cannot impersonate") {
				// Not an exemption failure: the runner's own kubeconfig cannot impersonate a
				// service account, so the exemption was never exercised. Distinguished because
				// the two failures send you to completely different places.
				Fail(fmt.Sprintf("this spec impersonates %s to check the service-account exemption, "+
					"and the test runner lacks impersonate on serviceaccounts: %v. Run it with a "+
					"kubeconfig that has it; nothing is known about the exemption either way.",
					authzExemptServiceAccount, exemptErr))
			}
			Expect(exemptErr).To(Succeed(), "an exempt Calico service account should still be able to read "+
				"policies while the webhook is down; check the matchConditions exempt list in "+
				"webhooks/config/authorization-configuration.yaml",
			)

			By("Verifying Calico's own components stay ready")
			// A supplementary signal, not the assertion that covers the exemption: established
			// watches are not re-authorized, so a component that neither restarts nor issues a
			// fresh request during the window would stay ready either way.
			Consistently(fx.calicoComponentsReady, 30*time.Second, 5*time.Second).Should(
				Succeed(), "Calico's components should be unaffected by a webhook outage",
			)

			By("Verifying pod connectivity still works")
			checker.ExpectSuccess(cl, server.ClusterIPs()...)
			checker.Execute()
		})
	},
)

// tieredRBACFixture is the per-spec setup shared by every tiered RBAC suite, the write-path one
// in tiered_rbac.go included: two tiers, the RBAC for every test user, and cleanup for all of it.
type tieredRBACFixture struct {
	f         *framework.Framework
	adminCli  ctrlclient.Client
	ctx       context.Context
	testTier  string
	otherTier string
	suffix    string
}

// setupTieredRBACFixture creates the fixture's cluster state and registers its cleanup. Call
// it from a BeforeEach. Cleanup is registered per resource so that LIFO ordering runs it after
// anything a spec registers later, notably the policies the specs create inside the tiers.
func setupTieredRBACFixture(f *framework.Framework) *tieredRBACFixture {
	// Long enough for every caller: the polling specs wait out a 30s decision cache more than
	// once, and the outage spec waits for the webhook to come back.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	DeferCleanup(cancel)

	adminCli, err := client.New(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred())

	fx := &tieredRBACFixture{
		f:        f,
		adminCli: adminCli,
		ctx:      ctx,
		suffix:   utils.GenerateRandomName("rbac"),
	}
	fx.testTier = "e2e-rbac-test-" + fx.suffix
	fx.otherTier = "e2e-rbac-other-" + fx.suffix

	By("Creating test tiers")
	for i, name := range []string{fx.testTier, fx.otherTier} {
		tier := v3.NewTier()
		tier.Name = name
		tier.Spec.Order = ptr.To(500.0 + float64(i))
		tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
		Expect(fx.adminCli.Create(ctx, tier)).To(Succeed(), "failed to create tier %s", name)

		tierName := name
		DeferCleanup(func() {
			toDelete := v3.NewTier()
			toDelete.Name = tierName
			fx.deleteQuietly(toDelete)
		})
	}

	By("Creating RBAC resources for test users")
	setup := buildTieredRBACResources(fx.testTier, fx.otherTier, fx.suffix)
	for i := range setup.roles {
		_, err := f.ClientSet.RbacV1().ClusterRoles().Create(ctx, &setup.roles[i], metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(fx.deleteClusterRole, setup.roles[i].Name)
	}
	for i := range setup.bindings {
		_, err := f.ClientSet.RbacV1().ClusterRoleBindings().Create(ctx, &setup.bindings[i], metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(fx.deleteClusterRoleBinding, setup.bindings[i].Name)
	}

	return fx
}

// impersonate returns a client that acts as the named user.
func (fx *tieredRBACFixture) impersonate(username string) ctrlclient.Client {
	cfg := rest.CopyConfig(fx.f.ClientConfig())
	cfg.Impersonate = rest.ImpersonationConfig{UserName: username}
	c, err := client.NewAPIClient(cfg)
	Expect(err).NotTo(HaveOccurred())
	return c
}

// createNetworkPolicy creates a NetworkPolicy in the test namespace as admin, and registers
// its deletion. The name carries the fixture's suffix so parallel specs cannot collide.
func (fx *tieredRBACFixture) createNetworkPolicy(name, tier string) *v3.NetworkPolicy {
	np := v3.NewNetworkPolicy()
	np.Name = "rbac-test-" + name + "-" + fx.suffix
	np.Namespace = fx.f.Namespace.Name
	np.Spec.Tier = tier
	np.Spec.Order = ptr.To(100.0)
	np.Spec.Selector = "all()"
	np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
	Expect(fx.adminCli.Create(fx.ctx, np)).To(Succeed(), "admin failed to create NetworkPolicy %s", np.Name)
	DeferCleanup(fx.deleteQuietly, np)
	return np
}

// createGlobalNetworkPolicy creates a GlobalNetworkPolicy as admin, and registers its deletion.
func (fx *tieredRBACFixture) createGlobalNetworkPolicy(name, tier string) *v3.GlobalNetworkPolicy {
	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "rbac-test-" + name + "-" + fx.suffix
	gnp.Spec.Tier = tier
	gnp.Spec.Order = ptr.To(100.0)
	gnp.Spec.Selector = "all()"
	gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
	Expect(fx.adminCli.Create(fx.ctx, gnp)).To(Succeed(), "admin failed to create GlobalNetworkPolicy %s", gnp.Name)
	DeferCleanup(fx.deleteQuietly, gnp)
	return gnp
}

// grantTierGet gives the user GET on one tier, and registers cleanup. Separate from
// buildTieredRBACResources because the recovery spec needs to add a grant part-way through.
func (fx *tieredRBACFixture) grantTierGet(name, user, tier string) {
	fullName := rbacResourcePrefix + name + "-" + fx.suffix
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: fullName},
		Rules: []rbacv1.PolicyRule{{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{tier},
		}},
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: fullName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     fullName,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "User",
			Name:     user,
		}},
	}

	_, err := fx.f.ClientSet.RbacV1().ClusterRoles().Create(fx.ctx, role, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(fx.deleteClusterRole, fullName)

	_, err = fx.f.ClientSet.RbacV1().ClusterRoleBindings().Create(fx.ctx, binding, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(fx.deleteClusterRoleBinding, fullName)
}

// scaleWebhook sets the authorization webhook Deployment's replica count, waits for the pod
// count to match, and registers a cleanup that restores the original count and waits for the
// webhook to serve again. Registered as a cleanup rather than done at the end of the spec so a
// failure part-way through does not leave every Calico request denied.
func (fx *tieredRBACFixture) scaleWebhook(replicas int32) {
	deployments, err := fx.f.ClientSet.AppsV1().Deployments("").List(fx.ctx, metav1.ListOptions{
		LabelSelector: webhookAppLabel,
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(deployments.Items).To(HaveLen(1),
		"expected exactly one Deployment matching %s, found %d", webhookAppLabel, len(deployments.Items))

	dep := deployments.Items[0]
	original := ptr.Deref(dep.Spec.Replicas, 1)
	Expect(original).To(BeNumerically(">", 0), "the webhook deployment is already scaled to zero")

	DeferCleanup(func() {
		By("Restoring the webhook deployment and waiting for it to serve again")
		fx.setReplicas(dep.Namespace, dep.Name, original)
		Eventually(func() error {
			// The admin identity is not exempt either, so an admin read succeeding is a
			// sufficient signal that the webhook is answering again.
			return fx.adminCli.List(context.Background(), &v3.NetworkPolicyList{},
				ctrlclient.InNamespace(fx.f.Namespace.Name),
				ctrlclient.MatchingLabels{v3.LabelTier: fx.testTier},
			)
		}, 5*time.Minute, 5*time.Second).Should(Succeed(), "the webhook did not recover")
	})

	fx.setReplicas(dep.Namespace, dep.Name, replicas)

	Eventually(func() (int, error) {
		pods, err := fx.f.ClientSet.CoreV1().Pods(dep.Namespace).List(fx.ctx, metav1.ListOptions{
			LabelSelector: webhookAppLabel,
		})
		if err != nil {
			return 0, err
		}
		return len(pods.Items), nil
	}, 2*time.Minute, 2*time.Second).Should(Equal(int(replicas)), "webhook pods did not reach the target count")
}

func (fx *tieredRBACFixture) setReplicas(namespace, name string, replicas int32) {
	scale, err := fx.f.ClientSet.AppsV1().Deployments(namespace).GetScale(
		context.Background(), name, metav1.GetOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	scale.Spec.Replicas = replicas
	_, err = fx.f.ClientSet.AppsV1().Deployments(namespace).UpdateScale(
		context.Background(), name, scale, metav1.UpdateOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
}

// calicoComponentsReady returns nil when every calico-node DaemonSet and every calico-typha
// Deployment in the cluster is fully ready. Typha is optional, so its absence is not an error,
// but a cluster with no calico-node at all is a detection failure rather than a pass.
func (fx *tieredRBACFixture) calicoComponentsReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodes, err := fx.f.ClientSet.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		return err
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("no DaemonSet matching k8s-app=calico-node found")
	}
	for _, ds := range nodes.Items {
		if ds.Status.DesiredNumberScheduled == 0 || ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("DaemonSet %s/%s has %d of %d pods ready",
				ds.Namespace, ds.Name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
		}
	}

	typhas, err := fx.f.ClientSet.AppsV1().Deployments("").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-typha",
	})
	if err != nil {
		return err
	}
	for _, dep := range typhas.Items {
		want := ptr.Deref(dep.Spec.Replicas, 1)
		if dep.Status.ReadyReplicas != want {
			return fmt.Errorf("deployment %s/%s has %d of %d replicas ready",
				dep.Namespace, dep.Name, dep.Status.ReadyReplicas, want)
		}
	}

	return nil
}

func (fx *tieredRBACFixture) deleteQuietly(obj ctrlclient.Object) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := fx.adminCli.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		logrus.WithError(err).WithField("name", obj.GetName()).Error("Failed to delete resource")
	}
}

func (fx *tieredRBACFixture) deleteClusterRole(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := fx.f.ClientSet.RbacV1().ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		logrus.WithError(err).WithField("name", name).Error("Failed to delete ClusterRole")
	}
}

func (fx *tieredRBACFixture) deleteClusterRoleBinding(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := fx.f.ClientSet.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		logrus.WithError(err).WithField("name", name).Error("Failed to delete ClusterRoleBinding")
	}
}

// inTierMessage returns the fragment a tier denial carries for the named tier. Both backends
// build it from the same forbiddenMessage in
// apiserver/pkg/registry/projectcalico/authorizer/authorizer.go, so pinning it distinguishes a
// tier denial from any other forbidden error on a resource whose name happens to contain "tier".
func inTierMessage(tier string) string {
	return fmt.Sprintf("in tier %q", tier)
}

// missingTierGetMessage is what forbiddenMessage appends when the user has the policy verb but
// not GET on the tier. Pinning it is what makes the no-tier-GET spec assert its own case rather
// than any tier denial.
const missingTierGetMessage = "(user cannot get tier)"

func npNames(list *v3.NetworkPolicyList) []string {
	names := make([]string, 0, len(list.Items))
	for _, p := range list.Items {
		names = append(names, p.Name)
	}
	return names
}

func gnpNames(list *v3.GlobalNetworkPolicyList) []string {
	names := make([]string, 0, len(list.Items))
	for _, p := range list.Items {
		names = append(names, p.Name)
	}
	return names
}

// requireAuthzWebhook fails the spec unless the Calico authorization webhook is in the
// kube-apiserver's authorization chain. A cluster without it skips; an inconclusive probe
// fails, because a probe that guesses wrong would make these specs meaningless.
func requireAuthzWebhook(cfg *rest.Config) {
	installed, err := authzWebhookInstalled(cfg)
	if err != nil {
		Fail(fmt.Sprintf(
			"Could not determine whether the Calico authorization webhook is installed: %v. "+
				"The probe issues an unselectored LIST of networkpolicies as a tier-restricted "+
				"user and expects either success (webhook absent) or a forbidden error naming %s "+
				"(webhook present).", err, v3.LabelTier,
		))
	}
	if !installed {
		msg := fmt.Sprintf(
			"This test requires the Calico authorization webhook in the kube-apiserver's " +
				"authorization chain (--authorization-config, see webhooks/config/README.md). " +
				"An unselectored LIST as a tier-restricted user was allowed, so tier RBAC is not " +
				"being enforced on reads by the webhook. Skip these tests with " +
				"-skip=RequiresAuthzWebhook.",
		)
		if describe.IncludesFocus("RequiresAuthzWebhook") {
			Fail(msg)
		}
		Skip(msg)
	}
}

// requireReadPathTierRBAC fails the spec unless something in the cluster enforces tier RBAC on
// reads: either the aggregated Calico API server or the authorization webhook.
func requireReadPathTierRBAC(cfg *rest.Config) {
	apiServer, err := calicoAPIServerPresent(cfg)
	Expect(err).NotTo(HaveOccurred())
	if apiServer {
		return
	}

	installed, err := authzWebhookInstalled(cfg)
	if err != nil {
		Fail(fmt.Sprintf(
			"No calico-apiserver pods were found, and could not determine whether the Calico "+
				"authorization webhook is installed: %v.", err,
		))
	}
	if installed {
		return
	}

	msg := "This test requires tier RBAC to be enforced on GET/LIST/WATCH, by either the " +
		"aggregated Calico API server or the Calico authorization webhook. Neither was " +
		"detected, so reads bypass tier RBAC entirely. Skip these tests with " +
		"-skip=RequiresReadPathTierRBAC."
	if describe.IncludesFocus("RequiresReadPathTierRBAC") {
		Fail(msg)
	}
	Skip(msg)
}

var (
	authzWebhookProbeMu   sync.Mutex
	authzWebhookProbeDone bool
	authzWebhookPresent   bool
)

// authzWebhookInstalled reports whether the Calico authorization webhook is in the API server's
// authorization chain. Only a conclusive answer is cached: that answer is a property of the
// cluster, and the probe writes cluster-scoped RBAC to get it. An error is deliberately not
// cached, so one inconclusive probe does not turn into a failure for every spec that follows.
func authzWebhookInstalled(cfg *rest.Config) (bool, error) {
	authzWebhookProbeMu.Lock()
	defer authzWebhookProbeMu.Unlock()

	if authzWebhookProbeDone {
		return authzWebhookPresent, nil
	}
	present, err := probeAuthzWebhook(cfg)
	if err != nil {
		return false, err
	}
	authzWebhookPresent, authzWebhookProbeDone = present, true
	return present, nil
}

// probeAuthzWebhook detects the authorization webhook behaviorally. Nothing in the API surface
// exposes the authorization chain: AuthorizationConfiguration is a file on the control plane.
// So issue the request whose treatment defines the feature. As a user whose GET on tiers is
// restricted to a named tier, an unselectored LIST of networkpolicies is:
//
//   - refused by the authorization webhook, because an unselectored list authorizes as an
//     unnamed request and RBAC matches those only against rules without resourceNames;
//   - allowed by the aggregated API server, which narrows the result to the tiers the user can
//     see instead of refusing;
//   - allowed outright by a cluster with neither;
//   - rejected as an unknown resource by a cluster that does not serve projectcalico.org/v3 at
//     all, which is also "not installed".
//
// The probe user is granted the default tier so that the aggregated API server's narrowing path
// has at least one tier to return; with no visible tiers it would refuse the list, and the
// probe would mistake that for the webhook.
func probeAuthzWebhook(cfg *rest.Config) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}

	suffix := utils.GenerateRandomName("probe")
	name := rbacResourcePrefix + suffix
	user := "e2e-rbac-webhook-probe-" + suffix

	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"tiers"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"default"},
			},
			{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"tier.networkpolicies"},
				Verbs:         []string{"get", "list", "watch"},
				ResourceNames: []string{"default.*"},
			},
		},
	}
	if _, err := cs.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
		return false, fmt.Errorf("failed to create the probe ClusterRole: %w", err)
	}
	defer func() {
		if err := cs.RbacV1().ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			logrus.WithError(err).WithField("name", name).Error("Failed to delete probe ClusterRole")
		}
	}()

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "User",
			Name:     user,
		}},
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		return false, fmt.Errorf("failed to create the probe ClusterRoleBinding: %w", err)
	}
	defer func() {
		if err := cs.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			logrus.WithError(err).WithField("name", name).Error("Failed to delete probe ClusterRoleBinding")
		}
	}()

	probeCfg := rest.CopyConfig(cfg)
	probeCfg.Impersonate = rest.ImpersonationConfig{UserName: user}
	cli, err := client.NewAPIClient(probeCfg)
	if err != nil {
		return false, err
	}

	// Poll, because the RBAC just created has to reach the API server's authorizer before the
	// probe means anything. Any other outcome is inconclusive and eventually reported as an
	// error rather than guessed at.
	var detected, stillUnserved bool
	var lastErr error
	pollErr := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute, true,
		func(ctx context.Context) (bool, error) {
			err := cli.List(ctx, &v3.NetworkPolicyList{})
			switch {
			case err == nil:
				detected = false
				return true, nil
			case apierrors.IsForbidden(err) && strings.Contains(err.Error(), v3.LabelTier):
				detected = true
				return true, nil
			case calicoV3Unserved(err):
				// Not conclusive on its own. A RESTMapper whose discovery cache was populated
				// before the v3 CRDs were established answers NoKindMatchError once and serves
				// the group fine thereafter, and treating that as "not installed" would skip
				// every gated spec for the rest of the run. Only a group that is still unserved
				// when the window expires means the feature is absent.
				stillUnserved, lastErr = true, err
				return false, nil
			default:
				stillUnserved, lastErr = false, err
				return false, nil
			}
		})
	if pollErr != nil {
		if stillUnserved {
			return false, nil
		}
		if lastErr == nil {
			return false, fmt.Errorf("the probe LIST never returned a conclusive result: %w", pollErr)
		}
		return false, fmt.Errorf("the probe LIST never returned a conclusive result: last error: %w", lastErr)
	}

	return detected, nil
}

// calicoV3Unserved reports whether err means the API server does not serve projectcalico.org/v3.
// Persisting for the whole poll window, it means "feature not installed" rather than a probe
// failure. The probe talks to the API directly; a cluster that reaches Calico resources only
// through the calicoctl fallback client (see e2e/pkg/utils/client.New) fails every poll this way,
// and without this arm it would exhaust the poll and fail every read-path spec instead of
// skipping them. One occurrence is not enough: see the caller.
func calicoV3Unserved(err error) bool {
	return meta.IsNoMatchError(err) || apierrors.IsNotFound(err)
}
