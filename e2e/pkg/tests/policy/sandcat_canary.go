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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("NetworkPolicy"),
	describe.WithCategory(describe.Policy),
	framework.WithConformance(),
	"sandcat canary",
	func() {
		f := utils.NewDefaultFramework("sandcat-canary")

		It("reaches a server that denies all ingress", func(ctx context.Context) {
			checker := conncheck.NewConnectionTester(f)
			server := conncheck.NewServer("server", f.Namespace)
			client := conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(client)
			checker.Deploy()
			DeferCleanup(checker.Stop)

			deny := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-server-ingress", Namespace: f.Namespace.Name},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pod-name": server.Name()}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				},
			}
			_, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, deny, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			checker.ExpectSuccess(client, server.ClusterIP())
			checker.Execute()
		})

		It("is blocked from a server with no policy", func() {
			checker := conncheck.NewConnectionTester(f)
			server := conncheck.NewServer("server", f.Namespace)
			client := conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(client)
			checker.Deploy()
			DeferCleanup(checker.Stop)

			checker.ExpectFailure(client, server.ClusterIP())
			checker.Execute()
		})
	})
