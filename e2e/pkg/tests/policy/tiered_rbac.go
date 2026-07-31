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
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

const (
	// Impersonated user names.
	rbacTierAdminUser    = "e2e-rbac-tier-admin"
	rbacNoTierGetUser    = "e2e-rbac-no-tier-get"
	rbacNoPolicyUser     = "e2e-rbac-no-policy-access"
	rbacOtherTierUser    = "e2e-rbac-other-tier-admin"
	rbacReadOnlyUser     = "e2e-rbac-read-only"
	rbacExactNameUser    = "e2e-rbac-exact-name"
	rbacWatchUser        = "e2e-rbac-watch"
	rbacWatchNoTierUser  = "e2e-rbac-watch-no-tier"
	rbacBareNameUser     = "e2e-rbac-bare-name"
	rbacPrefixedNameUser = "e2e-rbac-prefixed-name"

	// Common prefix for RBAC resources created by these tests.
	rbacResourcePrefix = "e2e-tiered-rbac-"
)

// DESCRIPTION: Verify tiered RBAC correctly enforces tier-based access control
// for policy create, update, and delete operations using bare policy names
// (without tier prefix). This naming style is only supported in v3.32+.
// Older branches should skip these tests via -skip=NoTierPrefix.
//
// The tiered RBAC implementation requires that users have:
//  1. GET access to the tier (resource: "tiers")
//  2. The required verb on either the specific policy or all policies in the tier
//     (resource: "tier.networkpolicies" / "tier.globalnetworkpolicies")
//
// PRECONDITIONS: The tiered RBAC webhook or Calico API server must be installed.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	describe.WithNoTierPrefix(),
	"Tiered RBAC",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac")

		var (
			adminCli  ctrlclient.Client
			ctx       context.Context
			cancel    context.CancelFunc
			testTier  string
			otherTier string
			suffix    string
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
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
			DeferCleanup(cancel)

			adminCli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			suffix = utils.GenerateRandomName("rbac")
			testTier = "e2e-rbac-test-" + suffix
			otherTier = "e2e-rbac-other-" + suffix

			By("Creating test tiers")
			for _, t := range []struct {
				name  string
				order float64
			}{
				{testTier, 500},
				{otherTier, 501},
			} {
				tier := v3.NewTier()
				tier.Name = t.name
				tier.Spec.Order = ptr.To(t.order)
				tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
				Expect(adminCli.Create(ctx, tier)).To(Succeed(), "failed to create tier %s", t.name)

				// Tier cleanup is registered per-tier so LIFO ordering ensures
				// it runs after any policy DeferCleanup registered in It blocks.
				tierName := t.name
				DeferCleanup(func() {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cleanupCancel()
					toDelete := v3.NewTier()
					toDelete.Name = tierName
					if err := adminCli.Delete(cleanupCtx, toDelete); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", tierName).Error("Failed to delete Tier")
					}
				})
			}

			By("Creating RBAC resources for test users")
			setup := buildTieredRBACResources(testTier, otherTier, suffix)
			for i := range setup.roles {
				_, err := f.ClientSet.RbacV1().ClusterRoles().Create(ctx, &setup.roles[i], metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				roleName := setup.roles[i].Name
				DeferCleanup(func() {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cleanupCancel()
					if err := f.ClientSet.RbacV1().ClusterRoles().Delete(cleanupCtx, roleName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", roleName).Error("Failed to delete ClusterRole")
					}
				})
			}
			for i := range setup.bindings {
				_, err := f.ClientSet.RbacV1().ClusterRoleBindings().Create(ctx, &setup.bindings[i], metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				bindingName := setup.bindings[i].Name
				DeferCleanup(func() {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cleanupCancel()
					if err := f.ClientSet.RbacV1().ClusterRoleBindings().Delete(cleanupCtx, bindingName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", bindingName).Error("Failed to delete ClusterRoleBinding")
					}
				})
			}
		})

		Context("NetworkPolicy", func() {
			framework.ConformanceIt("should allow creation by a user with full tier RBAC", func() {
				cli := newImpersonatedClient(rbacTierAdminUser)

				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-allow-create"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = testTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, np)
				Expect(err).NotTo(HaveOccurred())

				Expect(adminCli.Delete(ctx, np)).To(Succeed())
			})

			framework.ConformanceIt("should deny creation by a user without tier GET access", func() {
				cli := newImpersonatedClient(rbacNoTierGetUser)

				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-deny-no-get"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = testTier
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
				np.Spec.Tier = testTier
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
				np.Spec.Tier = testTier
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
				np.Spec.Tier = testTier
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
				np.Spec.Tier = testTier
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
				gnp.Spec.Tier = testTier
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
				gnp.Spec.Tier = testTier
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
			framework.ConformanceIt("should restrict a user to only their permitted tier", func() {
				cli := newImpersonatedClient(rbacOtherTierUser)

				By("Creating a policy in the permitted tier should succeed")
				gnp := v3.NewGlobalNetworkPolicy()
				gnp.Name = "rbac-test-other-allowed"
				gnp.Spec.Tier = otherTier
				gnp.Spec.Order = ptr.To(100.0)
				gnp.Spec.Selector = "all()"
				gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

				err := cli.Create(ctx, gnp)
				Expect(err).NotTo(HaveOccurred())
				Expect(adminCli.Delete(ctx, gnp)).To(Succeed())

				By("Creating a policy in a non-permitted tier should be denied")
				gnp2 := v3.NewGlobalNetworkPolicy()
				gnp2.Name = "rbac-test-other-denied"
				gnp2.Spec.Tier = testTier
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
			framework.ConformanceIt("should allow reading but deny writing for a read-only user", func() {
				By("Creating a policy with the admin client")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-read-only"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = testTier
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
				newNP.Spec.Tier = testTier
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

		// Verifies that Calico's tier-scoped resource name convention works for
		// exact resource names. A user with get/update/delete on a specific
		// tier.policyName should be able to operate on that policy but not others.
		// Note: create is excluded because K8s RBAC does not carry a resource name
		// on create requests, so resourceNames filtering is meaningless for create.
		//
		// Requires the aggregated API server because this test verifies GET-path
		// tier RBAC, which the admission webhook cannot enforce.
		framework.Context("resource-name exact match", describe.RequiresCalicoAPIServer(), func() {
			BeforeEach(func() { requireCalicoAPIServer(f.ClientConfig()) })
			It("should allow access to the named policy but deny access to others", func() {
				cli := newImpersonatedClient(rbacExactNameUser)

				By("Creating the target policy as admin")
				allowed := v3.NewNetworkPolicy()
				allowed.Name = "rbac-test-exact-allowed"
				allowed.Namespace = f.Namespace.Name
				allowed.Spec.Tier = testTier
				allowed.Spec.Order = ptr.To(100.0)
				allowed.Spec.Selector = "all()"
				allowed.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, allowed)).To(Succeed(), "admin failed to create target policy")
				DeferCleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := adminCli.Delete(cleanupCtx, allowed); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", allowed.Name).Error("Failed to delete policy")
					}
				})

				By("Verifying the exact-name user can get the named policy")
				got := v3.NewNetworkPolicy()
				Expect(cli.Get(ctx, ctrlclient.ObjectKeyFromObject(allowed), got)).To(Succeed(),
					"user with exact resource name should be able to get that specific policy")

				By("Verifying the exact-name user can update the named policy")
				got.Spec.Order = ptr.To(200.0)
				Expect(cli.Update(ctx, got)).To(Succeed(),
					"user with exact resource name should be able to update that specific policy")

				By("Creating a second policy as admin to test denial")
				other := v3.NewNetworkPolicy()
				other.Name = "rbac-test-exact-denied"
				other.Namespace = f.Namespace.Name
				other.Spec.Tier = testTier
				other.Spec.Order = ptr.To(100.0)
				other.Spec.Selector = "all()"
				other.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, other)).To(Succeed(), "admin failed to create second policy")
				DeferCleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := adminCli.Delete(cleanupCtx, other); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", other.Name).Error("Failed to delete policy")
					}
				})

				By("Verifying the exact-name user cannot get a differently-named policy")
				denied := v3.NewNetworkPolicy()
				err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(other), denied)
				Expect(err).To(HaveOccurred(), "user with exact resource name should not be able to get other policies")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			})
		})

		// Verifies that a user with list permissions scoped to a tier's policies
		// can list policies within that tier, and that a user without tier
		// policy access is denied.
		//
		// Requires the aggregated API server because this test verifies LIST-path
		// tier RBAC, which the admission webhook cannot enforce.
		framework.Context("list via tier RBAC", describe.RequiresCalicoAPIServer(), func() {
			BeforeEach(func() { requireCalicoAPIServer(f.ClientConfig()) })
			It("should allow listing policies in the permitted tier", func() {
				By("Creating a policy in the test tier")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-watch-target"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = testTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed(), "admin failed to create watch target policy")
				DeferCleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := adminCli.Delete(cleanupCtx, np); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", np.Name).Error("Failed to delete policy")
					}
				})

				cli := newImpersonatedClient(rbacWatchUser)

				By("Listing policies in the test tier namespace")
				list := &v3.NetworkPolicyList{}
				err := cli.List(ctx, list, ctrlclient.InNamespace(f.Namespace.Name))
				Expect(err).NotTo(HaveOccurred(), "user with list permission should be able to list policies")

				// Verify the created policy is in the list.
				found := false
				for _, p := range list.Items {
					if p.Name == np.Name {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "expected to find policy %s in list", np.Name)
			})

			// Verifies that a user with base networkpolicies list but no
			// tier.networkpolicies permission and no tier GET is denied by
			// the tier authorizer. This proves the tier expansion path is
			// enforced and that base K8s RBAC alone is not sufficient.
			It("should deny listing when user lacks tier policy access", func() {
				By("Creating a policy in the test tier")
				np := v3.NewNetworkPolicy()
				np.Name = "rbac-test-watch-denied"
				np.Namespace = f.Namespace.Name
				np.Spec.Tier = testTier
				np.Spec.Order = ptr.To(100.0)
				np.Spec.Selector = "all()"
				np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, np)).To(Succeed(), "admin failed to create policy for watch denial test")
				DeferCleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := adminCli.Delete(cleanupCtx, np); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", np.Name).Error("Failed to delete policy")
					}
				})

				cli := newImpersonatedClient(rbacWatchNoTierUser)

				By("Verifying the user without tier policy access cannot list policies")
				list := &v3.NetworkPolicyList{}
				err := cli.List(ctx, list, ctrlclient.InNamespace(f.Namespace.Name))
				Expect(err).To(HaveOccurred(), "user without tier policy access should not be able to list policies")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			})
		})

		// Verifies that old-style (tier-prefixed) and new-style (bare) policy
		// names are independently addressable via RBAC. Creates two policies
		// in the same tier whose names would collide under naive tier-prefix
		// logic, then proves each user can only access the policy their RBAC
		// grants match.
		//
		// Requires the aggregated API server because this test verifies GET-path
		// tier RBAC, which the admission webhook cannot enforce.
		framework.Context("old-style vs new-style name disambiguation", describe.RequiresCalicoAPIServer(), func() {
			BeforeEach(func() { requireCalicoAPIServer(f.ClientConfig()) })
			const bareName = "rbac-test-disambig"

			It("should independently authorize bare and tier-prefixed policy names", func() {
				prefixedName := testTier + "." + bareName

				By("Creating a bare-named policy (new-style)")
				barePolicy := v3.NewNetworkPolicy()
				barePolicy.Name = bareName
				barePolicy.Namespace = f.Namespace.Name
				barePolicy.Spec.Tier = testTier
				barePolicy.Spec.Order = ptr.To(100.0)
				barePolicy.Spec.Selector = "all()"
				barePolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, barePolicy)).To(Succeed(), "admin failed to create bare-named policy")
				DeferCleanup(func() {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cleanupCancel()
					if err := adminCli.Delete(cleanupCtx, barePolicy); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", barePolicy.Name).Error("Failed to delete policy")
					}
				})

				By("Creating a tier-prefixed policy (old-style)")
				prefixedPolicy := v3.NewNetworkPolicy()
				prefixedPolicy.Name = prefixedName
				prefixedPolicy.Namespace = f.Namespace.Name
				prefixedPolicy.Spec.Tier = testTier
				prefixedPolicy.Spec.Order = ptr.To(101.0)
				prefixedPolicy.Spec.Selector = "all()"
				prefixedPolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
				Expect(adminCli.Create(ctx, prefixedPolicy)).To(Succeed(), "admin failed to create tier-prefixed policy")
				DeferCleanup(func() {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cleanupCancel()
					if err := adminCli.Delete(cleanupCtx, prefixedPolicy); err != nil && !apierrors.IsNotFound(err) {
						logrus.WithError(err).WithField("name", prefixedPolicy.Name).Error("Failed to delete policy")
					}
				})

				bareNameCli := newImpersonatedClient(rbacBareNameUser)
				prefixedNameCli := newImpersonatedClient(rbacPrefixedNameUser)

				By("Verifying bare-name user can get the bare-named policy")
				got := v3.NewNetworkPolicy()
				Expect(bareNameCli.Get(ctx, ctrlclient.ObjectKeyFromObject(barePolicy), got)).To(Succeed(),
					"bare-name user should be able to get the bare-named policy")

				By("Verifying bare-name user cannot get the tier-prefixed policy")
				got = v3.NewNetworkPolicy()
				err := bareNameCli.Get(ctx, ctrlclient.ObjectKeyFromObject(prefixedPolicy), got)
				Expect(err).To(HaveOccurred(), "bare-name user should not be able to get the prefixed policy")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden, got: %v", err)

				By("Verifying prefixed-name user can get the tier-prefixed policy")
				got = v3.NewNetworkPolicy()
				Expect(prefixedNameCli.Get(ctx, ctrlclient.ObjectKeyFromObject(prefixedPolicy), got)).To(Succeed(),
					"prefixed-name user should be able to get the prefixed policy")

				By("Verifying prefixed-name user cannot get the bare-named policy")
				got = v3.NewNetworkPolicy()
				err = prefixedNameCli.Get(ctx, ctrlclient.ObjectKeyFromObject(barePolicy), got)
				Expect(err).To(HaveOccurred(), "prefixed-name user should not be able to get the bare-named policy")
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden, got: %v", err)
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
//
// testTier, otherTier, and suffix are passed in so each spec can use
// per-run random names. That way a previous spec that crashed mid-flight
// (e.g. the calico-apiserver briefly went unavailable) and left resources
// behind cannot 409 the next spec's creates, and parallel specs don't
// collide on cluster-scoped resources.
func buildTieredRBACResources(testTier, otherTier, suffix string) tieredRBACSetup {
	setup := tieredRBACSetup{}

	addRoleAndBinding := func(name, user string, rules []rbacv1.PolicyRule) {
		fullName := rbacResourcePrefix + name + "-" + suffix
		setup.roles = append(setup.roles, rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: fullName},
			Rules:      rules,
		})
		setup.bindings = append(setup.bindings, rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: fullName},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     fullName,
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
			ResourceNames: []string{testTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{testTier + ".*"},
		},
	))

	// No tier GET: has tier policy access but lacks the required GET on the tier resource.
	// RBAC should deny because tier GET is required alongside policy access.
	addRoleAndBinding("no-tier-get", rbacNoTierGetUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{testTier + ".*"},
		},
	))

	// No policy access: has tier GET but lacks permission on tier.networkpolicies.
	// RBAC should deny because policy-level access is required.
	addRoleAndBinding("no-policy", rbacNoPolicyUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier},
		},
	))

	// Other tier admin: full access but scoped to a different tier (otherTier).
	// Should be able to create in otherTier but denied in testTier.
	addRoleAndBinding("other-tier", rbacOtherTierUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{otherTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"create", "update", "delete", "get"},
			ResourceNames: []string{otherTier + ".*"},
		},
	))

	// Exact name: has tier GET and policy access for a specific resource name only
	// (not the wildcard). Should be able to get/update/delete the exact named policy
	// but not others. Note: create is excluded because K8s RBAC does not carry a
	// resource name on create requests, so resourceNames filtering cannot restrict it.
	addRoleAndBinding("exact-name", rbacExactNameUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies"},
			Verbs:         []string{"update", "delete", "get"},
			ResourceNames: []string{"rbac-test-exact-allowed"},
		},
	))

	// Watch user: has tier GET, base networkpolicies access, and tier-scoped
	// list/watch on tier.networkpolicies. The ResourceNames wildcard on
	// tier.networkpolicies is how Calico's authorizer checks tier-scoped
	// access: for list/watch (which have no resource name in K8s RBAC), the
	// authorizer explicitly queries with the synthetic name "tier.*", which
	// matches the ResourceNames entry.
	addRoleAndBinding("watch", rbacWatchUser, []rbacv1.PolicyRule{
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{testTier + ".*"},
		},
	})

	// Watch-no-tier user: has base networkpolicies list but NO
	// tier.networkpolicies permission and no tier GET. If the tier authorizer
	// enforces list operations, this user should be denied even though
	// base K8s RBAC allows listing networkpolicies.
	addRoleAndBinding("watch-no-tier", rbacWatchNoTierUser, []rbacv1.PolicyRule{
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
	})

	// Bare-name user: has tier GET and exact-name access for the bare policy
	// name "rbac-test-disambig" (without tier prefix). Used in the disambiguation
	// test to prove old-style and new-style names are independently addressable.
	addRoleAndBinding("bare-name", rbacBareNameUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"rbac-test-disambig"},
		},
	))

	// Prefixed-name user: has tier GET and exact-name access for the
	// tier-prefixed policy name "e2e-rbac-test.rbac-test-disambig" (old-style).
	addRoleAndBinding("prefixed-name", rbacPrefixedNameUser, append(baseRules(),
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier},
		},
		rbacv1.PolicyRule{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies"},
			Verbs:         []string{"get"},
			ResourceNames: []string{testTier + ".rbac-test-disambig"},
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
			ResourceNames: []string{testTier},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tier.networkpolicies", "tier.globalnetworkpolicies"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{testTier + ".*"},
		},
	})

	return setup
}

// DESCRIPTION: Verify tiered RBAC using tier-prefixed policy names (e.g., "tier.policyname"),
// which is supported on all Calico versions. This provides basic tiered RBAC coverage on
// older branches where the bare-name tests above are skipped.
//
// PRECONDITIONS: The tiered RBAC webhook or Calico API server must be installed.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-RBAC"),
	"Tiered RBAC with tier-prefixed names",
	func() {
		f := utils.NewDefaultFramework("tiered-rbac-prefixed")

		var (
			adminCli  ctrlclient.Client
			ctx       context.Context
			cancel    context.CancelFunc
			testTier  string
			otherTier string
			suffix    string
		)

		BeforeEach(func() {
			var err error
			ctx, cancel = context.WithCancel(context.Background())

			adminCli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			suffix = utils.GenerateRandomName("rbac")
			testTier = "e2e-rbac-test-" + suffix
			otherTier = "e2e-rbac-other-" + suffix

			By("Creating test tier")
			tier := v3.NewTier()
			tier.Name = testTier
			tier.Spec.Order = ptr.To(500.0)
			tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
			Expect(adminCli.Create(ctx, tier)).To(Succeed())

			By("Creating RBAC resources for test users")
			setup := buildTieredRBACResources(testTier, otherTier, suffix)
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
			setup := buildTieredRBACResources(testTier, otherTier, suffix)
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

			By("Cleaning up test tier")
			tier := v3.NewTier()
			tier.Name = testTier
			if err := adminCli.Delete(ctx, tier); err != nil {
				logrus.WithError(err).WithField("name", testTier).Error("Failed to delete Tier")
				errOccurred = true
			}

			Expect(errOccurred).To(BeFalse(), "errors occurred during teardown")
		})

		It("should allow create and deny based on tier RBAC with prefixed names", func() {
			By("Creating a policy as the tier admin using tier-prefixed name")
			cfg := rest.CopyConfig(f.ClientConfig())
			cfg.Impersonate = rest.ImpersonationConfig{UserName: rbacTierAdminUser}
			cli, err := client.NewAPIClient(cfg)
			Expect(err).NotTo(HaveOccurred())

			np := v3.NewNetworkPolicy()
			np.Name = testTier + "." + "rbac-test-prefixed-allow"
			np.Namespace = f.Namespace.Name
			np.Spec.Tier = testTier
			np.Spec.Order = ptr.To(100.0)
			np.Spec.Selector = "all()"
			np.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

			Expect(cli.Create(ctx, np)).To(Succeed(), "tier admin should be able to create policy with prefixed name")
			Expect(adminCli.Delete(ctx, np)).To(Succeed())

			By("Verifying a user without tier GET is denied with prefixed name")
			cfg2 := rest.CopyConfig(f.ClientConfig())
			cfg2.Impersonate = rest.ImpersonationConfig{UserName: rbacNoTierGetUser}
			noCli, err := client.NewAPIClient(cfg2)
			Expect(err).NotTo(HaveOccurred())

			np2 := v3.NewNetworkPolicy()
			np2.Name = testTier + "." + "rbac-test-prefixed-deny"
			np2.Namespace = f.Namespace.Name
			np2.Spec.Tier = testTier
			np2.Spec.Order = ptr.To(100.0)
			np2.Spec.Selector = "all()"
			np2.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}

			err = noCli.Create(ctx, np2)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected forbidden error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring("tier"))
		})
	},
)

// requireCalicoAPIServer checks that the aggregated Calico API server is
// deployed (as opposed to v3 CRD mode). In v3 CRD mode, GET/LIST/WATCH
// requests bypass tier RBAC because the admission webhook only covers
// mutating operations. Tests that verify read-path tier RBAC enforcement
// must call this in a BeforeEach so they fail immediately with a clear
// message when the API server is absent.
func requireCalicoAPIServer(cfg *rest.Config) {
	cs, err := kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-apiserver",
	})
	Expect(err).NotTo(HaveOccurred())
	if len(pods.Items) == 0 {
		Fail(fmt.Sprintf(
			"This test requires the aggregated Calico API server (calico-apiserver), " +
				"but no calico-apiserver pods were found. In v3 CRD mode, GET/LIST/WATCH " +
				"requests bypass tier RBAC because the admission webhook only covers " +
				"CREATE/UPDATE/DELETE. Deploy the aggregated API server or skip these " +
				"tests with -skip=RequiresCalicoAPIServer.",
		))
	}
}
