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
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

const (
	// Test tier names.
	rbacTestTier  = "e2e-rbac-test"
	rbacOtherTier = "e2e-rbac-other"

	// Impersonated user names.
	rbacTierAdminUser = "e2e-rbac-tier-admin"
	rbacNoTierGetUser = "e2e-rbac-no-tier-get"
	rbacNoPolicyUser  = "e2e-rbac-no-policy-access"
	rbacOtherTierUser = "e2e-rbac-other-tier-admin"
	rbacReadOnlyUser  = "e2e-rbac-read-only"

	// Common prefix for RBAC resources created by these tests.
	rbacResourcePrefix = "e2e-tiered-rbac-"
)

// DESCRIPTION: Verify tiered RBAC correctly enforces tier-based access control
// for policy create, update, and delete operations.
//
// The tiered RBAC implementation requires that users have:
//  1. GET access to the tier (resource: "tiers")
//  2. The required verb on either the specific policy or all policies in the tier
//     (resource: "tier.networkpolicies" / "tier.globalnetworkpolicies")
//
// PRECONDITIONS: The tiered RBAC webhook or Calico API server must be installed. Tiers are cluster-scoped,
// so these tests must run serially.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	describe.WithSerial(),
	"Tiered RBAC",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac")

		var (
			adminCli ctrlclient.Client
			ctx      context.Context
			cancel   context.CancelFunc
		)

		// newImpersonatedClient creates a controller-runtime client that impersonates the given user.
		newImpersonatedClient := func(username string) ctrlclient.Client {
			cfg := rest.CopyConfig(f.ClientConfig())
			cfg.Impersonate = rest.ImpersonationConfig{
				UserName: username,
			}
			c, err := client.NewAPIClient(cfg)
			Expect(err).NotTo(HaveOccurred())
			return c
		}

		BeforeEach(func() {
			var err error
			ctx, cancel = context.WithCancel(context.Background())

			adminCli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			Expect(utils.CleanDatastore(adminCli)).ShouldNot(HaveOccurred())

			By("Creating test tiers")
			for _, t := range []struct {
				name  string
				order float64
			}{
				{rbacTestTier, 500},
				{rbacOtherTier, 501},
			} {
				tier := v3.NewTier()
				tier.Name = t.name
				tier.Spec.Order = ptr.To(t.order)
				tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
				Expect(adminCli.Create(ctx, tier)).To(Succeed())
			}

			By("Creating RBAC resources for test users")
			setup := buildTieredRBACResources()
			for i := range setup.roles {
				_, err := f.ClientSet.RbacV1().ClusterRoles().Create(ctx, &setup.roles[i], metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
			for i := range setup.bindings {
				_, err := f.ClientSet.RbacV1().ClusterRoleBindings().Create(ctx, &setup.bindings[i], metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			defer cancel()
			var errOccurred bool

			By("Cleaning up RBAC resources")
			setup := buildTieredRBACResources()
			for _, binding := range setup.bindings {
				if err := f.ClientSet.RbacV1().ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil {
					logrus.WithError(err).WithField("name", binding.Name).Error("Failed to delete ClusterRoleBinding")
					errOccurred = true
				}
			}
			for _, role := range setup.roles {
				if err := f.ClientSet.RbacV1().ClusterRoles().Delete(ctx, role.Name, metav1.DeleteOptions{}); err != nil {
					logrus.WithError(err).WithField("name", role.Name).Error("Failed to delete ClusterRole")
					errOccurred = true
				}
			}

			By("Cleaning up test tiers")
			for _, name := range []string{rbacTestTier, rbacOtherTier} {
				tier := v3.NewTier()
				tier.Name = name
				if err := adminCli.Delete(ctx, tier); err != nil {
					logrus.WithError(err).WithField("name", name).Error("Failed to delete Tier")
					errOccurred = true
				}
			}

			Expect(errOccurred).To(BeFalse(), "errors occurred during teardown")
		})

		Context("NetworkPolicy", func() {
			It("should allow creation by a user with full tier RBAC", func() {
				cli := newImpersonatedClient(rbacTierAdminUser)

				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-allow-create"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, np)
				Expect(err).NotTo(HaveOccurred())

				Expect(adminCli.Delete(ctx, np)).To(Succeed())
			})

			It("should deny creation by a user without tier GET access", func() {
				cli := newImpersonatedClient(rbacNoTierGetUser)

				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-deny-no-get"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, np)
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
				Expect(err.Error()).To(ContainSubstring("tier"))
			})

			It("should deny creation by a user without tier policy access", func() {
				cli := newImpersonatedClient(rbacNoPolicyUser)

				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-deny-no-policy"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, np)
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
				Expect(err.Error()).To(ContainSubstring("tier"))
			})

			It("should allow deletion by a user with full tier RBAC", func() {
				By("Creating a policy with the admin client")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-allow-delete"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed())

				By("Deleting the policy as the tier admin user")
				cli := newImpersonatedClient(rbacTierAdminUser)
				Expect(cli.Delete(ctx, np)).To(Succeed())
			})

			// Verifies that the update verb is checked through the same tier RBAC
			// authorization path as create and delete.
			It("should allow update by a user with full tier RBAC", func() {
				By("Creating a policy with the admin client")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-allow-update"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed(), "admin failed to create policy for update test")

				By("Updating the policy as the tier admin user")
				cli := newImpersonatedClient(rbacTierAdminUser)
				Expect(cli.Get(ctx, ctrlclient.ObjectKeyFromObject(np), np)).To(
					Succeed(), "tier admin failed to get policy",
				)
				np.Spec.Order = ptr.To(200.0)
				Expect(cli.Update(ctx, np)).To(Succeed(), "tier admin should be able to update policy")

				Expect(adminCli.Delete(ctx, np)).To(Succeed())
			})

			// Verifies that update is denied when the user lacks tier GET access,
			// even though they have update permission on tier.networkpolicies.
			It("should deny update by a user without tier GET access", func() {
				By("Creating a policy with the admin client")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-deny-update"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed(), "admin failed to create policy for update test")

				By("Fetching the policy as admin to get the resource version")
				Expect(adminCli.Get(ctx, ctrlclient.ObjectKeyFromObject(np), np)).To(
					Succeed(), "admin failed to get policy",
				)

				By("Attempting to update the policy without tier GET access")
				np.Spec.Order = ptr.To(200.0)
				cli := newImpersonatedClient(rbacNoTierGetUser)
				err := cli.Update(ctx, np)
				Expect(err).To(HaveOccurred(), "update should be denied without tier GET access")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)

				Expect(adminCli.Delete(ctx, np)).To(Succeed())
			})
		})

		Context("GlobalNetworkPolicy", func() {
			It("should allow creation by a user with full tier RBAC", func() {
				cli := newImpersonatedClient(rbacTierAdminUser)

				gnp := v3.NewGlobalNetworkPolicy()
				gnp.Name = "rbac-test-allow-gnp"
				gnp.Spec.Tier = rbacTestTier
				gnp.Spec.Order = ptr.To(100.0)
				gnp.Spec.Selector = "all()"
				gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, gnp)
				Expect(err).NotTo(HaveOccurred())

				Expect(adminCli.Delete(ctx, gnp)).To(Succeed())
			})

			It("should deny creation by a user without tier access", func() {
				cli := newImpersonatedClient(rbacNoTierGetUser)

				gnp := v3.NewGlobalNetworkPolicy()
				gnp.Name = "rbac-test-deny-gnp"
				gnp.Spec.Tier = rbacTestTier
				gnp.Spec.Order = ptr.To(100.0)
				gnp.Spec.Selector = "all()"
				gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, gnp)
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
				Expect(err.Error()).To(ContainSubstring("tier"))
			})
		})

		Context("tier isolation", func() {
			It("should restrict a user to only their permitted tier", func() {
				cli := newImpersonatedClient(rbacOtherTierUser)

				By("Creating a policy in the permitted tier should succeed")
				gnp := v3.NewGlobalNetworkPolicy()
				gnp.Name = "rbac-test-other-allowed"
				gnp.Spec.Tier = rbacOtherTier
				gnp.Spec.Order = ptr.To(100.0)
				gnp.Spec.Selector = "all()"
				gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, gnp)
				Expect(err).NotTo(HaveOccurred())
				Expect(adminCli.Delete(ctx, gnp)).To(Succeed())

				By("Creating a policy in a non-permitted tier should be denied")
				gnp2 := v3.NewGlobalNetworkPolicy()
				gnp2.Name = "rbac-test-other-denied"
				gnp2.Spec.Tier = rbacTestTier
				gnp2.Spec.Order = ptr.To(100.0)
				gnp2.Spec.Selector = "all()"
				gnp2.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err = cli.Create(ctx, gnp2)
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
				Expect(err.Error()).To(ContainSubstring("tier"))
			})
		})

		// The default tier is a built-in resource that must remain immutable.
		// Even an admin cannot update or delete it. Each test includes a
		// DeferCleanup safety net that restores the default tier if the
		// operation unexpectedly succeeds, so we don't leave the cluster broken.
		Context("default tier", func() {
			// restoreDefaultTier is a safety net for default tier tests. If the
			// tier was modified (ResourceVersion changed) it restores the saved
			// spec; if it was deleted it recreates it.
			restoreDefaultTier := func(saved *v3.Tier) {
				current := v3.NewTier()
				current.Name = "default"
				if err := adminCli.Get(ctx, ctrlclient.ObjectKeyFromObject(current), current); err != nil {
					// Tier was deleted, recreate it.
					restore := v3.NewTier()
					restore.Name = "default"
					restore.Spec = saved.Spec
					if err := adminCli.Create(ctx, restore); err != nil {
						logrus.WithError(err).Error("CRITICAL: failed to recreate deleted default tier")
					}
					return
				}
				if current.ResourceVersion != saved.ResourceVersion {
					current.Spec = saved.Spec
					if err := adminCli.Update(ctx, current); err != nil {
						logrus.WithError(err).Warn("Failed to restore default tier")
					}
				}
			}

			It("should not allow updating the default tier", func() {
				tier := v3.NewTier()
				tier.Name = "default"
				Expect(adminCli.Get(ctx, ctrlclient.ObjectKeyFromObject(tier), tier)).To(
					Succeed(), "failed to get default tier",
				)

				savedTier := tier.DeepCopy()
				DeferCleanup(func() { restoreDefaultTier(savedTier) })

				tier.Spec.Order = ptr.To(999.0)
				err := adminCli.Update(ctx, tier)
				Expect(err).To(HaveOccurred(), "default tier should not be updatable")
			})

			It("should not allow deleting the default tier", func() {
				tier := v3.NewTier()
				tier.Name = "default"
				Expect(adminCli.Get(ctx, ctrlclient.ObjectKeyFromObject(tier), tier)).To(
					Succeed(), "failed to get default tier",
				)

				savedTier := tier.DeepCopy()
				DeferCleanup(func() { restoreDefaultTier(savedTier) })

				err := adminCli.Delete(ctx, tier)
				Expect(err).To(HaveOccurred(), "default tier should not be deletable")
			})
		})

		// Verifies that a user with read-only (get/list/watch) permissions on
		// tier policies can get existing policies but cannot create, update,
		// or delete them.
		Context("read-only access", func() {
			It("should allow reading but deny writing for a read-only user", func() {
				By("Creating a policy with the admin client")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-read-only"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = rbacTestTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed(), "admin failed to create policy for read-only test")

				cli := newImpersonatedClient(rbacReadOnlyUser)

				By("Verifying the read-only user can get the policy")
				readNP := v3.NewNetworkPolicy()
				Expect(cli.Get(ctx, ctrlclient.ObjectKeyFromObject(np), readNP)).To(
					Succeed(), "read-only user should be able to get policy",
				)

				By("Verifying the read-only user cannot create a policy")
				newNP := v3.NewNetworkPolicy()
				newNP.Name = "rbac-test-read-only-create"
				newNP.Namespace = f.Namespace.Name
				newNP.Spec.Tier = rbacTestTier
				newNP.Spec.Order = ptr.To(100.0)
				newNP.Spec.Selector = "all()"
				newNP.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				err := cli.Create(ctx, newNP)
				Expect(err).To(HaveOccurred(), "read-only user should not be able to create policy")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)

				By("Verifying the read-only user cannot update the policy")
				readNP.Spec.Order = ptr.To(200.0)
				err = cli.Update(ctx, readNP)
				Expect(err).To(HaveOccurred(), "read-only user should not be able to update policy")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)

				By("Verifying the read-only user cannot delete the policy")
				err = cli.Delete(ctx, np)
				Expect(err).To(HaveOccurred(), "read-only user should not be able to delete policy")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)

				Expect(adminCli.Delete(ctx, np)).To(Succeed())
			})
		})
	},
)

// tieredRBACSetup holds the RBAC resources needed for the tiered RBAC tests.
type tieredRBACSetup struct {
	roles    []rbacv1.ClusterRole
	bindings []rbacv1.ClusterRoleBinding
}

// buildTieredRBACResources constructs the ClusterRoles and ClusterRoleBindings needed for the
// tiered RBAC test users. Each user gets a different set of permissions to test different
// authorization outcomes:
//
//   - rbacTierAdminUser: full tier access (tier GET + tier policy wildcard)
//   - rbacNoTierGetUser: has tier policy access but NO tier GET
//   - rbacNoPolicyUser: has tier GET but NO tier policy access
//   - rbacOtherTierUser: full access but only for a different tier
//   - rbacReadOnlyUser: read-only access (get/list/watch) on tier policies
func buildTieredRBACResources() tieredRBACSetup {
	setup := tieredRBACSetup{}

	addRoleAndBinding := func(name, user string, rules []rbacv1.PolicyRule) {
		setup.roles = append(setup.roles, rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: rbacResourcePrefix + name},
			Rules:      rules,
		})
		setup.bindings = append(setup.bindings, rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: rbacResourcePrefix + name},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     rbacResourcePrefix + name,
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     user,
				},
			},
		})
	}

	// baseRules returns the standard API server RBAC rules that all test users need.
	baseRules := func() []rbacv1.PolicyRule {
		return []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies", "globalnetworkpolicies"},
				Verbs:     []string{"create", "update", "delete", "get", "list", "watch"},
			},
		}
	}

	// Tier admin: has GET on the test tier + wildcard policy access for the test tier.
	addRoleAndBinding("tier-admin", rbacTierAdminUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{rbacTestTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{rbacTestTier + ".*"},
		},
	))

	// No tier GET: has tier policy access but lacks the required GET on the tier resource.
	// RBAC should deny because tier GET is required alongside policy access.
	addRoleAndBinding("no-tier-get", rbacNoTierGetUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{rbacTestTier + ".*"},
		},
	))

	// No policy access: has tier GET but lacks permission on tier.networkpolicies.
	// RBAC should deny because policy-level access is required.
	addRoleAndBinding("no-policy", rbacNoPolicyUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{rbacTestTier},
		},
	))

	// Other tier admin: full access but scoped to a different tier (rbacOtherTier).
	// Should be able to create in rbacOtherTier but denied in rbacTestTier.
	addRoleAndBinding("other-tier", rbacOtherTierUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{rbacOtherTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{rbacOtherTier + ".*"},
		},
	))

	// Read-only: has tier GET and read-only policy access (get/list/watch).
	// Should be able to get/list/watch policies but not create, update, or delete.
	addRoleAndBinding("read-only", rbacReadOnlyUser, []rbacv1.PolicyRule{
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networkpolicies", "globalnetworkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{rbacTestTier},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{rbacTestTier + ".*"},
		},
	})

	return setup
}
