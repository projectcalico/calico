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

package validation_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

const annEth1NetworkStatus = "cni.projectcalico.org/eth1" + conversion.AnnotationNetworkStatusSuffix

// annotation is one key and the value a test writes to it.
type annotation struct {
	key   string
	value string
}

// protectedAnnotations are the keys the policy reserves.
var protectedAnnotations = []annotation{
	{conversion.AnnotationPodIP, "192.168.0.1"},
	{conversion.AnnotationPodIPs, "192.168.0.1,fd00::1"},
	{conversion.AnnotationContainerID, "abc123"},
	{conversion.AnnotationPodNetns, "/proc/1234/ns/net"},
	{conversion.AnnotationNetworkStatus, `{"name":"vlan100","vlan":100,"mac":"ee:ee:00:00:00:01"}`},
	{annEth1NetworkStatus, `{"name":"vlan200","vlan":200,"mac":"ee:ee:00:00:00:02"}`},
}

// User-input annotations under the same prefix, which anyone may set.
var userInputAnnotations = []annotation{
	{"cni.projectcalico.org/ipAddrs", `["192.168.0.1"]`},
	{"cni.projectcalico.org/ipAddrsNoIpam", `["10.0.0.1"]`},
	{"cni.projectcalico.org/hwAddr", "ee:ee:00:00:00:01"},
	{"cni.projectcalico.org/networks", "vlan100"},
	{"cni.projectcalico.org/vlan", "100"},
}

// Other owners' annotations. The Multus keys share the .network-status suffix.
var foreignAnnotations = []annotation{
	{"k8s.v1.cni.cncf.io/network-status", `[{"name":"k8s-pod-network","interface":"eth0"}]`},
	{"k8s.v1.cni.cncf.io/sdf.network-status", `[{"name":"sdf","interface":"net1"}]`},
	{"example.com/unrelated", "value"},
}

// The identities the policy exempts.
var exemptWriters = []string{
	"system:serviceaccount:calico-system:calico-cni-plugin",
	"system:serviceaccount:kube-system:calico-cni-plugin",
	"system:serviceaccount:kube-system:canal",
}

const (
	cniPluginUser       = "system:serviceaccount:calico-system:calico-cni-plugin"
	tenantUser          = "tenant-editor"
	cniAnnotationDenial = "Only Calico may set, change or remove these pod annotations"
	cniAnnotationHint   = "set spec.cni.annotationProtection to Disabled"
	policyName          = "protect-cni-annotations.projectcalico.org"
	podWritePath        = "pods"
	podStatusWritePath  = "pods/status"
)

// cniAnnotationPolicyPath returns the path of the shipped policy.
func cniAnnotationPolicyPath() string {
	return filepath.Join(testutils.FindRepoRoot(), "api", "admission", "k8s", "protect-cni-annotations.yaml")
}

// TestProtectCNIAnnotations_PolicyShape checks the shipped YAML.
func TestProtectCNIAnnotations_PolicyShape(t *testing.T) {
	policy, binding := loadCNIAnnotationPolicy(t)

	if policy.Name != policyName {
		t.Errorf("expected the policy to be named %q, got %q", policyName, policy.Name)
	}
	if binding.Name != policyName {
		t.Errorf("expected the binding to be named %q, got %q", policyName, binding.Name)
	}
	if binding.Spec.PolicyName != policyName {
		t.Errorf("expected the binding to reference %q, got %q", policyName, binding.Spec.PolicyName)
	}

	wantActions := []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
	if !slices.Equal(binding.Spec.ValidationActions, wantActions) {
		t.Errorf("expected the binding to deny, got %v", binding.Spec.ValidationActions)
	}

	if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Errorf("expected failurePolicy Fail, got %v", policy.Spec.FailurePolicy)
	}

	if policy.Spec.MatchConstraints == nil || len(policy.Spec.MatchConstraints.ResourceRules) != 1 {
		t.Fatalf("expected exactly one resource rule, got %+v", policy.Spec.MatchConstraints)
	}
	rule := policy.Spec.MatchConstraints.ResourceRules[0]

	if !slices.Equal(rule.APIGroups, []string{""}) {
		t.Errorf("expected the rule to match the core API group, got %v", rule.APIGroups)
	}
	if !slices.Equal(rule.APIVersions, []string{"v1"}) {
		t.Errorf("expected the rule to match v1, got %v", rule.APIVersions)
	}

	// pods/* would include pods/exec, which carries no metadata.
	if !slices.Equal(rule.Resources, []string{podWritePath, podStatusWritePath}) {
		t.Errorf("expected the rule to match exactly [pods pods/status], got %v", rule.Resources)
	}

	wantOps := []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
	if !slices.Equal(rule.Operations, wantOps) {
		t.Errorf("expected the rule to match exactly [CREATE UPDATE], got %v", rule.Operations)
	}

	protectedKeys := policyCELVariableExpression(t, policy, "protectedKeys")
	for _, a := range protectedAnnotations {
		if a.key == annEth1NetworkStatus {
			// Checked through perInterfaceKeys below.
			continue
		}
		if !strings.Contains(protectedKeys, a.key) {
			t.Errorf("expected the protectedKeys variable to name %q, got: %s", a.key, protectedKeys)
		}
	}

	// Without the prefix, other plugins' .network-status keys would be refused.
	perInterfaceKeys := policyCELVariableExpression(t, policy, "perInterfaceKeys")
	for _, want := range []string{"cni.projectcalico.org/", conversion.AnnotationNetworkStatusSuffix} {
		if !strings.Contains(perInterfaceKeys, want) {
			t.Errorf("expected the perInterfaceKeys variable to test for %q, got: %s", want, perInterfaceKeys)
		}
	}

	canDeletePolicy := policyCELVariableExpression(t, policy, "canDeletePolicy")
	if !strings.Contains(canDeletePolicy, "'"+policyName+"'") {
		t.Errorf("expected the canDeletePolicy variable to check this policy by name, got: %s", canDeletePolicy)
	}

	if len(policy.Spec.MatchConditions) == 0 {
		t.Fatal("expected the policy to carry a match condition exempting Calico")
	}
	for _, principal := range append(slices.Clone(exemptWriters), "system:masters") {
		if !slices.ContainsFunc(policy.Spec.MatchConditions, func(mc admissionregistrationv1.MatchCondition) bool {
			return strings.Contains(mc.Expression, principal)
		}) {
			t.Errorf("expected the policy to exempt %q", principal)
		}
	}

	if len(policy.Spec.Validations) == 0 {
		t.Fatal("expected the policy to carry at least one validation")
	}
	for i, v := range policy.Spec.Validations {
		if !strings.Contains(v.Message, cniAnnotationDenial) {
			t.Errorf("validation %d: expected message to contain %q, got %q", i, cniAnnotationDenial, v.Message)
		}
		if !strings.Contains(v.Message, cniAnnotationHint) {
			t.Errorf("validation %d: expected message to contain %q, got %q", i, cniAnnotationHint, v.Message)
		}
		if !strings.Contains(v.MessageExpression, cniAnnotationHint) {
			t.Errorf("validation %d: expected messageExpression to contain %q, got %q", i, cniAnnotationHint, v.MessageExpression)
		}
		if v.MessageExpression != "" && !strings.Contains(v.MessageExpression, cniAnnotationDenial) {
			t.Errorf("validation %d: expected messageExpression to contain %q, got %q", i, cniAnnotationDenial, v.MessageExpression)
		}
	}
}

// TestProtectCNIAnnotations_CreateRefused checks that a create carrying a protected key is refused.
func TestProtectCNIAnnotations_CreateRefused(t *testing.T) {
	requireCNIAnnotationPolicy(t)
	tenant := clientAs(t, tenantUser)

	for _, a := range protectedAnnotations {
		t.Run(a.key, func(t *testing.T) {
			pod := newTestPod(map[string]string{a.key: a.value})
			expectRefused(t, tenant.Create(context.Background(), pod), a.key)
		})
	}
}

// TestProtectCNIAnnotations_UpdateRefused checks that adding, changing or removing a protected key is refused.
func TestProtectCNIAnnotations_UpdateRefused(t *testing.T) {
	requireCNIAnnotationPolicy(t)
	tenant := clientAs(t, tenantUser)

	seeded := map[string]string{}
	for _, a := range protectedAnnotations {
		seeded[a.key] = a.value
	}

	for _, writePath := range []string{podWritePath, podStatusWritePath} {
		t.Run(writePath+"/add", func(t *testing.T) {
			pod := seedPod(t, map[string]string{conversion.AnnotationPodIP: "192.168.0.1"})
			expectRefused(t, updatePod(t, tenant, pod, writePath, func(p *corev1.Pod) {
				setAnnotation(p, annEth1NetworkStatus, `{"name":"vlan200","vlan":200}`)
			}), annEth1NetworkStatus)
		})

		for _, a := range protectedAnnotations {
			t.Run(writePath+"/change/"+a.key, func(t *testing.T) {
				pod := seedPod(t, seeded)
				expectRefused(t, updatePod(t, tenant, pod, writePath, func(p *corev1.Pod) {
					setAnnotation(p, a.key, a.value+"-forged")
				}), a.key)
			})

			t.Run(writePath+"/remove/"+a.key, func(t *testing.T) {
				pod := seedPod(t, seeded)
				expectRefused(t, updatePod(t, tenant, pod, writePath, func(p *corev1.Pod) {
					delete(p.Annotations, a.key)
				}), a.key)
			})
		}
	}
}

// TestProtectCNIAnnotations_PlainPodsUnaffected checks that Pods without Calico annotations are admitted.
func TestProtectCNIAnnotations_PlainPodsUnaffected(t *testing.T) {
	requireCNIAnnotationPolicy(t)

	for _, user := range []string{tenantUser, cniPluginUser} {
		t.Run(user+"/create with no annotations", func(t *testing.T) {
			mustCreatePodAs(t, clientAs(t, user), nil)
		})

		for _, writePath := range []string{podWritePath, podStatusWritePath} {
			t.Run(user+"/"+writePath+"/update a Pod with no annotations", func(t *testing.T) {
				c := clientAs(t, user)
				pod := mustCreatePodAs(t, c, nil)
				expectAllowed(t, updatePod(t, c, pod, writePath, func(p *corev1.Pod) {
					p.Labels = map[string]string{"touched": "yes"}
				}))
			})

			t.Run(user+"/"+writePath+"/annotate a Pod that never carried a Calico key", func(t *testing.T) {
				c := clientAs(t, user)
				pod := mustCreatePodAs(t, c, nil)
				expectAllowed(t, updatePod(t, c, pod, writePath, func(p *corev1.Pod) {
					setAnnotation(p, "example.com/added-later", "value")
				}))
			})
		}
	}
}

// TestProtectCNIAnnotations_CreateAllowsUserInput checks that user-input annotations are admitted.
func TestProtectCNIAnnotations_CreateAllowsUserInput(t *testing.T) {
	requireCNIAnnotationPolicy(t)
	tenant := clientAs(t, tenantUser)

	t.Run("all of them at once", func(t *testing.T) {
		mustCreatePodAs(t, tenant, annotationMap(userInputAnnotations))
	})

	for _, a := range userInputAnnotations {
		t.Run(a.key, func(t *testing.T) {
			mustCreatePodAs(t, tenant, map[string]string{a.key: a.value})
		})
	}
}

// TestProtectCNIAnnotations_AllowsOtherPluginsAnnotations checks that other plugins' annotations are admitted.
func TestProtectCNIAnnotations_AllowsOtherPluginsAnnotations(t *testing.T) {
	requireCNIAnnotationPolicy(t)
	tenant := clientAs(t, tenantUser)

	t.Run("create carrying all of them", func(t *testing.T) {
		mustCreatePodAs(t, tenant, annotationMap(foreignAnnotations))
	})

	for _, a := range foreignAnnotations {
		t.Run("create/"+a.key, func(t *testing.T) {
			mustCreatePodAs(t, tenant, map[string]string{a.key: a.value})
		})

		for _, writePath := range []string{podWritePath, podStatusWritePath} {
			t.Run(writePath+"/add/"+a.key, func(t *testing.T) {
				pod := mustCreatePodAs(t, tenant, nil)
				expectAllowed(t, updatePod(t, tenant, pod, writePath, func(p *corev1.Pod) {
					setAnnotation(p, a.key, a.value)
				}))
			})
		}
	}
}

// TestProtectCNIAnnotations_UntouchedWriteAllowed checks that a write leaving the protected keys alone is admitted.
func TestProtectCNIAnnotations_UntouchedWriteAllowed(t *testing.T) {
	requireCNIAnnotationPolicy(t)

	seeded := map[string]string{
		conversion.AnnotationPodIP:         "192.168.0.1",
		conversion.AnnotationNetworkStatus: `{"name":"vlan100","vlan":100}`,
		annEth1NetworkStatus:               `{"name":"vlan200","vlan":200}`,
	}

	for _, user := range []string{tenantUser, cniPluginUser} {
		for _, writePath := range []string{podWritePath, podStatusWritePath} {
			t.Run(user+"/"+writePath, func(t *testing.T) {
				c := clientAs(t, user)
				pod := seedPod(t, seeded)
				expectAllowed(t, updatePod(t, c, pod, writePath, func(p *corev1.Pod) {
					p.Labels = map[string]string{"touched": "yes"}
					setAnnotation(p, "example.com/unrelated", "value")
				}))
			})
		}
	}
}

// TestProtectCNIAnnotations_ExemptIdentitiesAllowed checks that the exempt identities can write the protected keys.
func TestProtectCNIAnnotations_ExemptIdentitiesAllowed(t *testing.T) {
	requireCNIAnnotationPolicy(t)

	seeded := map[string]string{
		conversion.AnnotationPodIP:         "192.168.0.1",
		conversion.AnnotationNetworkStatus: `{"name":"vlan100","vlan":100}`,
	}

	for _, user := range exemptWriters {
		t.Run(user, func(t *testing.T) {
			c := clientAs(t, user)
			pod := mustCreatePodAs(t, c, seeded)

			expectAllowed(t, updatePod(t, c, pod, podStatusWritePath, func(p *corev1.Pod) {
				setAnnotation(p, conversion.AnnotationPodIP, "192.168.0.2")
			}))

			expectAllowed(t, updatePod(t, c, pod, podStatusWritePath, func(p *corev1.Pod) {
				delete(p.Annotations, conversion.AnnotationNetworkStatus)
			}))
		})
	}

	// envtest's own client is in system:masters.
	t.Run("system:masters", func(t *testing.T) {
		mustCreatePodAs(t, testClient, seeded)
	})
}

// TestProtectCNIAnnotations_PolicyDeletersAllowed checks that anyone allowed to delete the policy
// can write the protected keys, and that permission to delete another policy is not enough.
func TestProtectCNIAnnotations_PolicyDeletersAllowed(t *testing.T) {
	requireCNIAnnotationPolicy(t)

	allowed := []struct {
		user  string
		rules []rbacv1.PolicyRule
		role  string
	}{
		{user: "cluster-admin-user", role: "cluster-admin"},
		{user: "cni-policy-deleter", rules: deletePolicyRules(policyName)},
	}
	for _, tc := range allowed {
		t.Run(tc.user, func(t *testing.T) {
			bindClusterRole(t, tc.user, tc.role, tc.rules)
			waitForPolicyDeleteAccess(t, tc.user, true)
			c := clientAs(t, tc.user)

			for _, a := range protectedAnnotations {
				pod := mustCreatePodAs(t, c, map[string]string{a.key: a.value})
				for _, path := range []string{podWritePath, podStatusWritePath} {
					expectAllowed(t, updatePod(t, c, pod, path, func(p *corev1.Pod) {
						setAnnotation(p, a.key, a.value+"-"+path)
					}))
				}
				expectAllowed(t, updatePod(t, c, pod, podStatusWritePath, func(p *corev1.Pod) {
					delete(p.Annotations, a.key)
				}))
			}
		})
	}

	t.Run("deleter of another policy", func(t *testing.T) {
		const user = "other-policy-deleter"
		bindClusterRole(t, user, "", deletePolicyRules("some-other-policy"))
		waitForPolicyDeleteAccess(t, user, false)
		tenant := clientAs(t, user)

		for _, a := range protectedAnnotations {
			pod := newTestPod(map[string]string{a.key: a.value})
			expectRefused(t, tenant.Create(context.Background(), pod), a.key)
		}
	})
}

// deletePolicyRules allows deleting the named ValidatingAdmissionPolicy and nothing else.
func deletePolicyRules(name string) []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{{
		APIGroups:     []string{"admissionregistration.k8s.io"},
		Resources:     []string{"validatingadmissionpolicies"},
		ResourceNames: []string{name},
		Verbs:         []string{"delete"},
	}}
}

// bindClusterRole binds user to the named ClusterRole, or to a new one carrying rules when
// role is empty, and removes whatever it created when the test ends.
func bindClusterRole(t *testing.T, user, role string, rules []rbacv1.PolicyRule) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("cni-ann-" + user)

	if role == "" {
		cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
		if err := testClient.Create(ctx, cr); err != nil {
			t.Fatalf("failed to create ClusterRole %s: %v", name, err)
		}
		t.Cleanup(func() { _ = testClient.Delete(context.Background(), cr) })
		role = name
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: user}},
	}
	if err := testClient.Create(ctx, crb); err != nil {
		t.Fatalf("failed to create ClusterRoleBinding %s: %v", name, err)
	}
	t.Cleanup(func() { _ = testClient.Delete(context.Background(), crb) })
}

// waitForPolicyDeleteAccess waits until the authorizer answers want for whether user may delete
// the policy. RBAC changes reach the authorizer asynchronously.
func waitForPolicyDeleteAccess(t *testing.T, user string, want bool) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	for {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: user,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Group:    "admissionregistration.k8s.io",
					Resource: "validatingadmissionpolicies",
					Name:     policyName,
					Verb:     "delete",
				},
			},
		}
		err := testClient.Create(ctx, sar)
		if err == nil && sar.Status.Allowed == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s may delete %s: wanted %v, still not after 30s (last error: %v)", user, policyName, want, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// loadCNIAnnotationPolicy reads the policy and its binding out of the shipped YAML.
func loadCNIAnnotationPolicy(t *testing.T) (*admissionregistrationv1.ValidatingAdmissionPolicy, *admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	t.Helper()

	data, err := os.ReadFile(cniAnnotationPolicyPath())
	if err != nil {
		t.Fatalf("failed to read the policy: %v", err)
	}

	var policy *admissionregistrationv1.ValidatingAdmissionPolicy
	var binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding
	for _, doc := range strings.Split(string(data), "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var kind struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &kind); err != nil {
			t.Fatalf("failed to read the kind of a document in %s: %v", cniAnnotationPolicyPath(), err)
		}
		switch kind.Kind {
		case "ValidatingAdmissionPolicy":
			policy = &admissionregistrationv1.ValidatingAdmissionPolicy{}
			if err := yaml.Unmarshal([]byte(doc), policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
		case "ValidatingAdmissionPolicyBinding":
			binding = &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
			if err := yaml.Unmarshal([]byte(doc), binding); err != nil {
				t.Fatalf("failed to parse the binding: %v", err)
			}
		default:
			t.Fatalf("unexpected kind %q in %s", kind.Kind, cniAnnotationPolicyPath())
		}
	}
	if policy == nil {
		t.Fatalf("%s carries no ValidatingAdmissionPolicy", cniAnnotationPolicyPath())
	}
	if binding == nil {
		t.Fatalf("%s carries no ValidatingAdmissionPolicyBinding", cniAnnotationPolicyPath())
	}
	return policy, binding
}

// policyCELVariableExpression returns the CEL of the named policy variable.
func policyCELVariableExpression(t *testing.T, policy *admissionregistrationv1.ValidatingAdmissionPolicy, name string) string {
	t.Helper()
	for _, v := range policy.Spec.Variables {
		if v.Name == name {
			return v.Expression
		}
	}
	t.Fatalf("the policy has no %q variable", name)
	return ""
}

// annotationMap collapses a table into the map a Pod carries.
func annotationMap(annotations []annotation) map[string]string {
	m := map[string]string{}
	for _, a := range annotations {
		m[a.key] = a.value
	}
	return m
}

// newTestPod returns a Pod carrying the given annotations; nil leaves it with none.
func newTestPod(annotations map[string]string) *corev1.Pod {
	var ann map[string]string
	if annotations != nil {
		ann = map[string]string{}
		for k, v := range annotations {
			ann[k] = v
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        uniqueName("cni-ann"),
			Namespace:   "default",
			Annotations: ann,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: "registry.k8s.io/pause:3.10"}},
		},
	}
}

// mustCreatePodAs creates a Pod as the given identity, asserts it was allowed, and
// registers its cleanup.
func mustCreatePodAs(t *testing.T, c client.Client, annotations map[string]string) *corev1.Pod {
	t.Helper()
	pod := newTestPod(annotations)
	if err := c.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected the create to be allowed, got: %v", err)
	}
	t.Cleanup(func() { _ = testClient.Delete(context.Background(), pod) })
	return pod
}

// seedPod creates a Pod as the CNI plugin, so it can carry protected keys.
func seedPod(t *testing.T, annotations map[string]string) *corev1.Pod {
	t.Helper()
	return mustCreatePodAs(t, clientAs(t, cniPluginUser), annotations)
}

// updatePod re-reads the Pod, applies mutate, and writes it back through pods or pods/status.
func updatePod(t *testing.T, c client.Client, pod *corev1.Pod, podPath string, mutate func(*corev1.Pod)) error {
	t.Helper()
	ctx := context.Background()

	got := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), got); err != nil {
		t.Fatalf("failed to read back the Pod: %v", err)
	}
	mutate(got)

	switch podPath {
	case podStatusWritePath:
		return c.Status().Update(ctx, got)
	case podWritePath:
		return c.Update(ctx, got)
	default:
		t.Fatalf("Unknown pod path for updating pod annotations '%s'", podPath)
	}

	return nil
}

// setAnnotation sets one annotation, creating the map if the Pod has none.
func setAnnotation(pod *corev1.Pod, key, value string) {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[key] = value
}

// expectRefused asserts that the policy refused the write and named key.
func expectRefused(t *testing.T, err error, key string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the write to be refused, but it was allowed")
	}
	if !strings.Contains(err.Error(), cniAnnotationDenial) {
		t.Fatalf("expected the write to be refused by the CNI annotation policy, got: %v", err)
	}
	if !strings.Contains(err.Error(), key) {
		t.Fatalf("expected the refusal to name %q, got: %v", key, err)
	}
	if !strings.Contains(err.Error(), cniAnnotationHint) {
		t.Fatalf("expected the refusal to say how to allow the write, got: %v", err)
	}
}

// expectAllowed asserts the write went through.
func expectAllowed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected the write to be allowed, got: %v", err)
	}
}

var (
	cniPolicyOnce sync.Once
	cniPolicyErr  error
)

// requireCNIAnnotationPolicy waits until the policy is enforcing.
func requireCNIAnnotationPolicy(t *testing.T) {
	t.Helper()
	if !k8sPoliciesEnabled {
		t.Skip("ValidatingAdmissionPolicy not supported on this K8s version")
	}
	tenant := clientAs(t, tenantUser)
	cniPolicyOnce.Do(func() { cniPolicyErr = waitForCNIAnnotationPolicy(tenant) })
	if cniPolicyErr != nil {
		t.Fatal(cniPolicyErr)
	}
}

// waitForCNIAnnotationPolicy polls until a Pod carrying a protected key is refused.
func waitForCNIAnnotationPolicy(c client.Client) error {
	ctx := context.Background()
	var lastErr error
	deadline := time.Now().Add(60 * time.Second)
	for {
		probe := newTestPod(map[string]string{conversion.AnnotationPodIP: "192.168.0.1"})
		lastErr = c.Create(ctx, probe)
		switch {
		case lastErr == nil:
			_ = testClient.Delete(ctx, probe)
		case strings.Contains(lastErr.Error(), cniAnnotationDenial):
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("a Pod carrying %s was still not refused after 60s; is %s installed and bound? last result: %v",
				conversion.AnnotationPodIP, cniAnnotationPolicyPath(), lastErr)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
