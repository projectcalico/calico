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
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	probeSuffix    = "rbac-abcde"
	probeTestTier  = "e2e-rbac-test-" + probeSuffix
	probeOtherTier = "e2e-rbac-other-" + probeSuffix
	probeNamespace = "tiered-rbac-1234"
)

// Every binding the suite creates gets a probe, and wherever the bound role
// carries a per-spec name the probe asks for it, so a parallel spec's grant to
// the same user cannot satisfy the wait.
func TestTieredRBACProbesCoverEveryBinding(t *testing.T) {
	g := NewWithT(t)

	setup := buildTieredRBACResources(probeTestTier, probeOtherTier, probeSuffix, probeNamespace, true)
	probes := tieredRBACProbes(setup)

	g.Expect(probes).To(HaveLen(len(setup.bindings) + len(setup.nsBindings)))

	var namespaced []*authorizationv1.SubjectAccessReview
	for _, p := range probes {
		attrs := p.Spec.ResourceAttributes
		g.Expect(p.Spec.User).NotTo(BeEmpty())
		g.Expect(attrs.Group).To(Equal("projectcalico.org"))
		g.Expect(attrs.Verb).NotTo(BeEmpty())
		g.Expect(attrs.Resource).NotTo(BeEmpty())

		// The watch-no-tier role has no name-scoped rule to prefer.
		if p.Spec.User == rbacWatchNoTierUser {
			g.Expect(attrs.Name).To(BeEmpty())
		} else {
			g.Expect(attrs.Name).To(ContainSubstring(probeSuffix), "probe for %s should ask for a per-spec name", p.Spec.User)
		}

		if attrs.Namespace != "" {
			namespaced = append(namespaced, p)
		}
	}

	g.Expect(namespaced).To(HaveLen(1))
	g.Expect(namespaced[0].Spec.User).To(Equal(rbacNamespacedUser))
	g.Expect(namespaced[0].Spec.ResourceAttributes.Namespace).To(Equal(probeNamespace))
	g.Expect(namespaced[0].Spec.ResourceAttributes.Resource).To(Equal("tier.networkpolicies"))
	g.Expect(namespaced[0].Spec.ResourceAttributes.Name).To(Equal(probeTestTier + ".*"))
}

func TestTieredRBACProbePrefersNamedRule(t *testing.T) {
	unnamed := rbacv1.PolicyRule{
		APIGroups: []string{"projectcalico.org"},
		Resources: []string{"networkpolicies"},
		Verbs:     []string{"get", "list"},
	}
	named := rbacv1.PolicyRule{
		APIGroups:     []string{"projectcalico.org"},
		Resources:     []string{"tiers"},
		Verbs:         []string{"get"},
		ResourceNames: []string{probeTestTier},
	}
	subject := rbacv1.Subject{Kind: "User", Name: rbacTierAdminUser}

	tests := []struct {
		name      string
		giveRules []rbacv1.PolicyRule
		wantAttrs *authorizationv1.ResourceAttributes
	}{
		{
			name:      "named rule wins over an earlier unnamed one",
			giveRules: []rbacv1.PolicyRule{unnamed, named},
			wantAttrs: &authorizationv1.ResourceAttributes{
				Namespace: probeNamespace,
				Verb:      "get",
				Group:     "projectcalico.org",
				Resource:  "tiers",
				Name:      probeTestTier,
			},
		},
		{
			name:      "first rule when none is named",
			giveRules: []rbacv1.PolicyRule{unnamed},
			wantAttrs: &authorizationv1.ResourceAttributes{
				Namespace: probeNamespace,
				Verb:      "get",
				Group:     "projectcalico.org",
				Resource:  "networkpolicies",
			},
		},
		{
			name: "no rules, no probe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got := tieredRBACProbe(subject, probeNamespace, tt.giveRules)
			if tt.wantAttrs == nil {
				g.Expect(got).To(BeNil())
				return
			}
			g.Expect(got).NotTo(BeNil())
			g.Expect(got.Spec.User).To(Equal(rbacTierAdminUser))
			g.Expect(got.Spec.ResourceAttributes).To(Equal(tt.wantAttrs))
		})
	}
}

func TestCheckTieredRBACProbesReportsFirstDenial(t *testing.T) {
	g := NewWithT(t)

	allowed := map[string]bool{}
	cs := fake.NewClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateAction)
		if !ok {
			return true, nil, errors.New("not a create action")
		}
		sar, ok := create.GetObject().(*authorizationv1.SubjectAccessReview)
		if !ok {
			return true, nil, errors.New("not a SubjectAccessReview")
		}
		out := sar.DeepCopy()
		out.Status.Allowed = allowed[sar.Spec.User]
		if !out.Status.Allowed {
			out.Status.Reason = "binding not yet observed"
		}
		return true, out, nil
	})

	probes := tieredRBACProbes(buildTieredRBACResources(probeTestTier, probeOtherTier, probeSuffix, probeNamespace, true))
	g.Expect(probes).NotTo(BeEmpty())

	err := checkTieredRBACProbes(context.Background(), cs, probes)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring(probes[0].Spec.User))
	g.Expect(err.Error()).To(ContainSubstring("binding not yet observed"))

	for _, p := range probes {
		allowed[p.Spec.User] = true
	}
	g.Expect(checkTieredRBACProbes(context.Background(), cs, probes)).To(Succeed())
}

func TestCheckTieredRBACProbesReturnsAPIErrors(t *testing.T) {
	g := NewWithT(t)

	cs := fake.NewClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})

	probes := tieredRBACProbes(buildTieredRBACResources(probeTestTier, probeOtherTier, probeSuffix, probeNamespace, true))
	err := checkTieredRBACProbes(context.Background(), cs, probes)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apiserver unavailable"))
}
