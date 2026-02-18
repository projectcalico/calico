// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

// DESCRIPTION: Verify Kubernetes watch API works correctly for Calico NetworkPolicy objects,
// including policies created in custom tiers that didn't exist when the watch started.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("NetworkPolicy"),
	describe.WithSerial(),
	"NetworkPolicy watch tests",
	func() {
		var cli ctrlclient.WithWatch
		f := utils.NewDefaultFramework("policy-watch")

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			err := v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			cli, err = ctrlclient.NewWithWatch(f.ClientConfig(), ctrlclient.Options{Scheme: scheme})
			Expect(err).NotTo(HaveOccurred())

			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())
		})

		// expectEvent reads from a watch channel until it finds an event matching
		// the given type and policy name, or times out. It returns the matched policy
		// so the caller can make additional assertions.
		expectEvent := func(watcher watch.Interface, eventType watch.EventType, name string) *v3.NetworkPolicy {
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			for {
				select {
				case event, ok := <-watcher.ResultChan():
					if !ok {
						Fail("watch channel closed unexpectedly")
						return nil
					}
					policy, ok := event.Object.(*v3.NetworkPolicy)
					if !ok {
						continue
					}
					if event.Type == eventType && policy.Name == name {
						return policy
					}
				case <-timer.C:
					Fail(fmt.Sprintf("timed out waiting for %s event on policy %s", eventType, name))
					return nil
				}
			}
		}

		// expectNoEvent asserts that no matching watch event arrives within the timeout.
		expectNoEvent := func(watcher watch.Interface, timeout time.Duration) {
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			for {
				select {
				case event, ok := <-watcher.ResultChan():
					if !ok {
						return
					}
					if _, ok := event.Object.(*v3.NetworkPolicy); ok {
						Fail(fmt.Sprintf("unexpected watch event: %s %v", event.Type, event.Object))
					}
				case <-timer.C:
					return
				}
			}
		}

		It("should receive watch events for created and deleted policies, including across new tiers", func() {
			ctx := context.Background()

			By("Starting a watch on NetworkPolicies before any resources are created")
			watcher, err := cli.Watch(ctx, &v3.NetworkPolicyList{}, ctrlclient.InNamespace(f.Namespace.Name))
			Expect(err).NotTo(HaveOccurred())
			defer watcher.Stop()

			By("Creating a NetworkPolicy in the default tier")
			defaultPolicy := v3.NewNetworkPolicy()
			defaultPolicy.Name = "watch-pol-default"
			defaultPolicy.Namespace = f.Namespace.Name
			defaultPolicy.Spec.Tier = "default"
			defaultPolicy.Spec.Selector = "all()"
			defaultPolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
			err = cli.Create(ctx, defaultPolicy)
			Expect(err).NotTo(HaveOccurred())

			By("Expecting an ADDED watch event for the default tier policy")
			expectEvent(watcher, watch.Added, defaultPolicy.Name)

			By("Deleting the default tier policy")
			err = cli.Delete(ctx, defaultPolicy)
			Expect(err).NotTo(HaveOccurred())

			By("Expecting a DELETED watch event for the default tier policy")
			expectEvent(watcher, watch.Deleted, defaultPolicy.Name)

			By("Creating a new tier that did not exist when the watch was established")
			tier := v3.NewTier()
			tier.Name = "watch-tier"
			tier.Spec.Order = ptr.To(100.0)
			tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
			err = cli.Create(ctx, tier)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, tier)
				Expect(err).NotTo(HaveOccurred())
			}()

			By("Creating a NetworkPolicy in the new tier")
			tierPolicy := v3.NewNetworkPolicy()
			tierPolicy.Name = "watch-tier.watch-pol-tier"
			tierPolicy.Namespace = f.Namespace.Name
			tierPolicy.Spec.Tier = "watch-tier"
			tierPolicy.Spec.Selector = "all()"
			tierPolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
			err = cli.Create(ctx, tierPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, tierPolicy)
				Expect(err).NotTo(HaveOccurred())
			}()

			By("Expecting an ADDED watch event for the policy in the new tier")
			p := expectEvent(watcher, watch.Added, tierPolicy.Name)
			Expect(p.Spec.Tier).To(Equal("watch-tier"))
		})

		It("should only receive events for the watched tier when using a field selector", func() {
			ctx := context.Background()

			By("Creating a custom tier to watch")
			tier := v3.NewTier()
			tier.Name = "fs-watch-tier"
			tier.Spec.Order = ptr.To(100.0)
			tier.Labels = map[string]string{utils.TestResourceLabel: "true"}
			err := cli.Create(ctx, tier)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, tier)
				Expect(err).NotTo(HaveOccurred())
			}()

			By("Starting a watch filtered to the custom tier using a field selector")
			watcher, err := cli.Watch(ctx, &v3.NetworkPolicyList{},
				ctrlclient.InNamespace(f.Namespace.Name),
				ctrlclient.MatchingFields{"spec.tier": "fs-watch-tier"},
			)
			Expect(err).NotTo(HaveOccurred())
			defer watcher.Stop()

			By("Creating a NetworkPolicy in the default tier (should be filtered out)")
			defaultPolicy := v3.NewNetworkPolicy()
			defaultPolicy.Name = "fs-watch-pol-default"
			defaultPolicy.Namespace = f.Namespace.Name
			defaultPolicy.Spec.Tier = "default"
			defaultPolicy.Spec.Selector = "all()"
			defaultPolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
			err = cli.Create(ctx, defaultPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, defaultPolicy)
				Expect(err).NotTo(HaveOccurred())
			}()

			By("Verifying no watch event is received for the default tier policy")
			expectNoEvent(watcher, 5*time.Second)

			By("Creating a NetworkPolicy in the watched tier")
			tierPolicy := v3.NewNetworkPolicy()
			tierPolicy.Name = "fs-watch-tier.fs-watch-pol-tier"
			tierPolicy.Namespace = f.Namespace.Name
			tierPolicy.Spec.Tier = "fs-watch-tier"
			tierPolicy.Spec.Selector = "all()"
			tierPolicy.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
			err = cli.Create(ctx, tierPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, tierPolicy)
				Expect(err).NotTo(HaveOccurred())
			}()

			By("Expecting an ADDED watch event for the policy in the watched tier")
			p := expectEvent(watcher, watch.Added, tierPolicy.Name)
			Expect(p.Spec.Tier).To(Equal("fs-watch-tier"))
		})
	},
)
