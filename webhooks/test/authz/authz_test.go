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

// This suite runs the authorization webhook the way a cluster does: a real kube-apiserver
// started with the shipped AuthorizationConfiguration, pointed at the real authz handler over
// TLS, deciding against the real tierauth core, the real policy tier cache, and the API
// server's own RBAC. Nothing on the API server side is faked.
//
// Three things can only be covered here. The matchConditions CEL expressions are evaluated by
// the API server, so a unit test cannot tell whether one filters the requests it is meant to.
// The SubjectAccessReview encoding is the API server's, not ours. And the decision cache TTLs
// live in the API server's webhook authorizer.
//
// Every spec uses a user of its own. The API server caches authorization decisions for
// unauthorizedTTL, so a user reused across specs could be answered from cache — which looks
// exactly like a matchCondition having filtered the request out.
package authz_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	authzcel "k8s.io/apiserver/pkg/authorization/cel"
	authzwebhook "k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	authzmetrics "k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/webhooks/pkg/authz"
	"github.com/projectcalico/calico/webhooks/pkg/policycache"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

func TestAuthzEnvtest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorization webhook envtest Suite")
}

const (
	// The service accounts the second matchCondition exempts. Spelled out here rather than
	// read back out of the config so that a typo introduced in the config fails the suite.
	exemptWebhookSA = "system:serviceaccount:kube-system:calico-webhooks"
	exemptNodeSA    = "system:serviceaccount:kube-system:calico-node"
	exemptKCSA      = "system:serviceaccount:kube-system:calico-kube-controllers"

	restrictedTier = "net-sec"
	otherTier      = "platform"
	testNamespace  = "default"

	// labeledPolicy carries the projectcalico.org/tier label, so the policy cache answers
	// from its informer. unlabeledPolicy does not, which forces the live-GET fallback.
	labeledPolicy   = "labeled-np"
	unlabeledPolicy = "unlabeled-np"

	// unauthorizedTTL replaces the shipped 30s so the decision-cache spec does not have to
	// wait that long for an entry to expire. It is the only value this suite overrides.
	//
	// It cuts both ways, so don't shorten it further: the spec's cache-hit assertion needs
	// both of its requests to land inside the TTL, and that half has no retry.
	unauthorizedTTL = 5 * time.Second
)

var (
	ctx         context.Context
	testEnv     *envtest.Environment
	adminCfg    *rest.Config
	adminClient kubernetes.Interface
	hook        *recorder
)

// recorder is the endpoint the API server's authorization webhook points at. It records every
// SubjectAccessReview that actually arrived, which is how a matchCondition is verified: a
// filtered request never reaches us at all. By default it answers from the real authz.Hook; a
// spec that needs a specific verdict installs a decide func instead.
type recorder struct {
	mu       sync.Mutex
	received []authorizationv1.SubjectAccessReview
	returned []authorizationv1.SubjectAccessReviewStatus

	authorizer *authz.Hook
	decide     func(authorizationv1.SubjectAccessReview) authorizationv1.SubjectAccessReviewStatus
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Decode with the webhook's own codecs, so that a change to the SubjectAccessReview the
	// API server sends shows up here rather than in production.
	obj, gvk, err := utils.Codecs.UniversalDeserializer().Decode(body, nil, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if want := authorizationv1.SchemeGroupVersion.WithKind("SubjectAccessReview"); *gvk != want {
		http.Error(w, fmt.Sprintf("got %v, want %v", gvk, want), http.StatusBadRequest)
		return
	}
	sar, ok := obj.(*authorizationv1.SubjectAccessReview)
	if !ok {
		http.Error(w, fmt.Sprintf("got %T", obj), http.StatusBadRequest)
		return
	}

	sar.Status = r.statusFor(*sar)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sar); err != nil {
		GinkgoWriter.Printf("failed to encode the response: %v\n", err)
	}
}

func (r *recorder) statusFor(sar authorizationv1.SubjectAccessReview) authorizationv1.SubjectAccessReviewStatus {
	r.mu.Lock()
	decide, hookUnderTest := r.decide, r.authorizer
	r.received = append(r.received, sar)
	r.mu.Unlock()

	var status authorizationv1.SubjectAccessReviewStatus
	switch {
	case decide != nil:
		status = decide(sar)
	case hookUnderTest != nil:
		status = *hookUnderTest.Authorize(sar)
	default:
		// BeforeSuite has not finished building the decision core yet. Answering NoOpinion
		// keeps the policy cache's own initial list from being denied.
		status = authorizationv1.SubjectAccessReviewStatus{}
	}

	r.mu.Lock()
	r.returned = append(r.returned, status)
	r.mu.Unlock()

	return status
}

// callsFor counts the reviews that arrived for a user and resource. Counting per user is what
// makes a zero meaningful: unrelated traffic from another identity cannot mask it.
func (r *recorder) callsFor(user, resource string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var n int
	for _, sar := range r.received {
		ra := sar.Spec.ResourceAttributes
		if sar.Spec.User == user && ra != nil && ra.Resource == resource {
			n++
		}
	}
	return n
}

// callsBy counts every review that arrived for a user, whatever it was about. Used for the
// non-resource request, which carries no resource to match on.
func (r *recorder) callsBy(user string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var n int
	for _, sar := range r.received {
		if sar.Spec.User == user {
			n++
		}
	}
	return n
}

func (r *recorder) responses() []authorizationv1.SubjectAccessReviewStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]authorizationv1.SubjectAccessReviewStatus(nil), r.returned...)
}

// reset returns the recorder to its default state: nothing recorded, and decisions answered by
// the real hook again.
func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received, r.returned, r.decide = nil, nil, nil
}

// clearCalls forgets what has been recorded but leaves the installed decider in place.
func (r *recorder) clearCalls() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received, r.returned = nil, nil
}

func (r *recorder) setDecider(decide func(authorizationv1.SubjectAccessReview) authorizationv1.SubjectAccessReviewStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decide = decide
}

func (r *recorder) setAuthorizer(a *authz.Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorizer = a
}

var _ = BeforeSuite(func() {
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.Background())

	hook = &recorder{}
	server := httptest.NewTLSServer(hook)
	DeferCleanup(server.Close)

	dir, err := os.MkdirTemp("", "authz-envtest")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

	configPath, err := writeAuthzConfig(dir, server.URL, pemEncode(server.Certificate()))
	Expect(err).NotTo(HaveOccurred())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join(testutils.FindRepoRoot(), "api", "config", "crd")},
	}
	if os.Getenv("AUTHZ_ENVTEST_VERBOSE") != "" {
		testEnv.ControlPlane.GetAPIServer().Out = GinkgoWriter
		testEnv.ControlPlane.GetAPIServer().Err = GinkgoWriter
	}
	// --authorization-config is mutually exclusive with --authorization-mode, which envtest
	// passes by default. The default has to be suppressed, not overridden: an API server given
	// both refuses to start.
	testEnv.ControlPlane.GetAPIServer().Configure().
		Disable("authorization-mode").
		Set("authorization-config", configPath)

	adminCfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred(),
		"the API server did not start; a matchConditions expression that fails to compile surfaces here. "+
			"Set AUTHZ_ENVTEST_VERBOSE=1 to see its output")
	DeferCleanup(func() {
		// Cancel first: the policy cache's watches are long-running requests, and the API
		// server's graceful shutdown waits them out rather than stopping under them.
		cancel()
		Expect(testEnv.Stop()).To(Succeed())
	})

	adminClient = kubernetes.NewForConfigOrDie(adminCfg)
	grantRBAC()
	createPolicies()

	// The webhook's own clients impersonate the exempt service account, as they do in a
	// cluster. Without the exemption the policy cache's live GET would be authorized through
	// the webhook that is asking for it, and the fallback path would recurse.
	webhookCfg := configFor(exemptWebhookSA)

	cache := policycache.New(
		metadata.NewForConfigOrDie(webhookCfg),
		calicoclient.NewForConfigOrDie(webhookCfg),
		10*time.Minute,
	)
	cache.Start(ctx)
	Expect(cache.WaitForSync(ctx)).To(Succeed())

	// Same construction as the webhook binary: tier decisions are answered by asking the API
	// server, so the RBAC the specs install is the RBAC that decides them.
	tierClient, err := authzwebhook.NewFromInterface(
		kubernetes.NewForConfigOrDie(webhookCfg).AuthorizationV1(),
		5*time.Second,
		5*time.Second,
		*authzwebhook.DefaultRetryBackoff(),
		kauth.DecisionDeny,
		&authzmetrics.NoopAuthorizerMetrics{},
		authzcel.NewDefaultCompiler(),
	)
	Expect(err).NotTo(HaveOccurred())

	hook.setAuthorizer(authz.NewHook(tierauth.New(authorizer.NewTierAuthorizer(tierClient), cache)))
})

// writeAuthzConfig writes the webhook kubeconfig and an AuthorizationConfiguration into dir,
// and returns the path to the latter. The configuration is the shipped file with the kubeconfig
// path and unauthorizedTTL retargeted, rather than a copy of it: the matchConditions this suite
// exists to exercise have to be the ones we install.
func writeAuthzConfig(dir, serverURL string, caPEM []byte) (string, error) {
	kubeconfigPath := filepath.Join(dir, "webhook-kubeconfig.yaml")
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: calico-authz
    cluster:
      server: %s/authz
      certificate-authority-data: %s
contexts:
  - name: calico-authz
    context:
      cluster: calico-authz
current-context: calico-authz
`, serverURL, base64.StdEncoding.EncodeToString(caPEM))
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0o600); err != nil {
		return "", err
	}

	shipped := filepath.Join(testutils.FindRepoRoot(), "webhooks", "config", "authorization-configuration.yaml")
	raw, err := os.ReadFile(shipped)
	if err != nil {
		return "", err
	}
	// Strict, so that a field name the API server would silently ignore fails here instead.
	var config apiserverv1.AuthorizationConfiguration
	if err := yaml.UnmarshalStrict(raw, &config); err != nil {
		return "", fmt.Errorf("parse %s: %w", shipped, err)
	}

	var found bool
	for i := range config.Authorizers {
		w := config.Authorizers[i].Webhook
		if w == nil {
			continue
		}
		w.ConnectionInfo.KubeConfigFile = &kubeconfigPath
		w.UnauthorizedTTL = metav1.Duration{Duration: unauthorizedTTL}
		found = true
	}
	if !found {
		return "", fmt.Errorf("%s declares no webhook authorizer", shipped)
	}

	out, err := yaml.Marshal(&config)
	if err != nil {
		return "", err
	}
	configPath := filepath.Join(dir, "authorization-configuration.yaml")
	return configPath, os.WriteFile(configPath, out, 0o600)
}

func pemEncode(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// The users the specs run as. One per spec, because the API server caches decisions.
const (
	userCoreRead      = "authz-core-read"
	userCRDGroup      = "authz-crd-group"
	userNonResource   = "authz-non-resource"
	userNearMissName  = "system:serviceaccount:kube-system:calico-typha"
	userNearMissNS    = "system:serviceaccount:default:calico-node"
	userNoTier        = "authz-no-tier"
	userUnrestricted  = "authz-unrestricted"
	userTierScoped    = "authz-tier-scoped"
	userNoBaseRBAC    = "authz-no-base-rbac"
	userCachedDeny    = "authz-cached-deny"
	userNamedAllowed  = "authz-named-allowed"
	userNamedDenied   = "authz-named-denied"
	userUnlabeledDeny = "authz-unlabeled-denied"
	userMutating      = "authz-mutating"
)

func grantRBAC() {
	// The webhook itself: it lists the resources it authorizes and asks the API server for
	// tier decisions.
	grant(exemptWebhookSA+":webhook", exemptWebhookSA,
		rbacv1.PolicyRule{
			APIGroups: []string{v3.GroupName},
			Resources: []string{"*"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
	)

	grant(userCoreRead+":core", userCoreRead, rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"configmaps"},
		Verbs:     []string{"list"},
	})

	// userCRDGroup and userNonResource are deliberately given nothing: their specs assert on
	// the webhook not being consulted, not on the request succeeding.

	for _, user := range []string{
		exemptWebhookSA, exemptNodeSA, exemptKCSA,
		userNearMissName, userNearMissNS,
		userNoTier, userUnrestricted, userTierScoped,
		userCachedDeny, userNamedAllowed, userNamedDenied, userUnlabeledDeny,
	} {
		grantPolicyRBAC(user, "get", "list", "watch")
	}
	grantPolicyRBAC(userMutating, "create")

	// userNoBaseRBAC gets tier access but no base access, which is what proves the webhook
	// never answers Allowed.
	grantTierRBAC(userNoBaseRBAC, restrictedTier)
	grantTierRBAC(userTierScoped, restrictedTier)
	grantTierRBAC(userNamedAllowed, restrictedTier)
	grantTierRBAC(userNamedDenied, otherTier)
	grantTierRBAC(userUnlabeledDeny, otherTier)
	grantTierRBAC(userUnrestricted, "")
}

// grantPolicyRBAC gives user the plain resource permission that RBAC checks once the webhook
// has returned NoOpinion. A spec expecting a request to get through fails on RBAC without it,
// which reads like a webhook deny but is not one.
func grantPolicyRBAC(user string, verbs ...string) {
	grant(user+":base", user, rbacv1.PolicyRule{
		APIGroups: []string{v3.GroupName},
		Resources: []string{"networkpolicies"},
		Verbs:     verbs,
	})
}

// grantTierRBAC gives user the tier-scoped permissions tierauth checks. An empty tier grants
// tier-unrestricted access: the rules carry no resourceNames, which is what RBAC matches the
// unnamed check behind an unselectored list against.
func grantTierRBAC(user, tier string) {
	var tierNames, policyNames []string
	if tier != "" {
		tierNames = []string{tier}
		policyNames = []string{tier + ".*"}
	}

	grant(user+":tier", user, rbacv1.PolicyRule{
		APIGroups:     []string{v3.GroupName},
		Resources:     []string{"tiers"},
		Verbs:         []string{"get"},
		ResourceNames: tierNames,
	}, rbacv1.PolicyRule{
		APIGroups:     []string{v3.GroupName},
		Resources:     []string{"tier.networkpolicies"},
		Verbs:         []string{"get", "list", "watch"},
		ResourceNames: policyNames,
	})
}

// grant creates a ClusterRole named role holding rules, bound to the named user. Service
// account identities are bound as User subjects on purpose: RBAC compares the subject name to
// the authenticated user name, and impersonation is the only thing creating them here.
func grant(role, user string, rules ...rbacv1.PolicyRule) {
	GinkgoHelper()

	_, err := adminClient.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: role},
		Rules:      rules,
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	_, err = adminClient.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: user}},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createPolicies() {
	GinkgoHelper()

	client := calicoclient.NewForConfigOrDie(adminCfg).ProjectcalicoV3()
	for _, p := range []*v3.NetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      labeledPolicy,
				Namespace: testNamespace,
				Labels:    map[string]string{v3.LabelTier: restrictedTier},
			},
			Spec: v3.NetworkPolicySpec{Tier: restrictedTier, Selector: "all()"},
		},
		{
			// No tier label, so the cache has to fall back to reading spec.tier live.
			ObjectMeta: metav1.ObjectMeta{Name: unlabeledPolicy, Namespace: testNamespace},
			Spec:       v3.NetworkPolicySpec{Tier: restrictedTier, Selector: "all()"},
		},
	} {
		_, err := client.NetworkPolicies(testNamespace).Create(ctx, p, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func configFor(user string) *rest.Config {
	cfg := rest.CopyConfig(adminCfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user}
	return cfg
}

func listPolicies(user string, opts metav1.ListOptions) error {
	_, err := calicoclient.NewForConfigOrDie(configFor(user)).
		ProjectcalicoV3().NetworkPolicies(testNamespace).List(ctx, opts)
	return err
}

func getPolicy(user, name string) error {
	_, err := calicoclient.NewForConfigOrDie(configFor(user)).
		ProjectcalicoV3().NetworkPolicies(testNamespace).Get(ctx, name, metav1.GetOptions{})
	return err
}

var _ = Describe("Calico authorization webhook", func() {
	BeforeEach(func() {
		hook.reset()
	})

	AfterEach(func() {
		// The webhook runs ahead of RBAC, so an Allowed response would grant base resource
		// permission the user does not have. Checked after every spec rather than in one of
		// them, because any spec is a chance to regress it.
		for _, status := range hook.responses() {
			Expect(status.Allowed).To(BeFalse(), "the webhook must only ever answer Denied or NoOpinion")
		}
	})

	Describe("the API group matchCondition", func() {
		It("keeps core group requests away from the webhook", func() {
			_, err := kubernetes.NewForConfigOrDie(configFor(userCoreRead)).
				CoreV1().ConfigMaps(testNamespace).List(ctx, metav1.ListOptions{})

			Expect(err).NotTo(HaveOccurred())
			Expect(hook.callsBy(userCoreRead)).To(Equal(0),
				"gating core resources would put a fail-closed webhook in front of cluster bootstrap")
		})

		It("keeps crd.projectcalico.org requests away from the webhook", func() {
			// The condition compares the group for equality. Calico owns two groups whose
			// names differ only by a prefix, so a looser comparison would catch both.
			gvr := schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "felixconfigurations"}
			_, err := dynamic.NewForConfigOrDie(configFor(userCRDGroup)).Resource(gvr).List(ctx, metav1.ListOptions{})

			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected RBAC to reject the request: %v", err)
			Expect(hook.callsBy(userCRDGroup)).To(Equal(0))
		})

		It("keeps non-resource requests away from the webhook", func() {
			// has(request.resourceAttributes) guards the group comparison. Drop the guard and
			// the API server rejects the whole expression at startup rather than failing this
			// request, so BeforeSuite is where that mistake surfaces.
			_, err := kubernetes.NewForConfigOrDie(configFor(userNonResource)).Discovery().ServerVersion()

			Expect(err).NotTo(HaveOccurred())
			Expect(hook.callsBy(userNonResource)).To(Equal(0))
		})

		It("consults the webhook for writes as well as reads", func() {
			// The condition carries no verb guard, so the webhook sees every verb on the
			// group and declines to have an opinion on the mutating ones itself.
			policy := &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "created-np", Namespace: testNamespace},
				Spec:       v3.NetworkPolicySpec{Selector: "all()"},
			}
			client := calicoclient.NewForConfigOrDie(configFor(userMutating)).ProjectcalicoV3()

			_, err := client.NetworkPolicies(testNamespace).Create(ctx, policy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				Expect(calicoclient.NewForConfigOrDie(adminCfg).ProjectcalicoV3().
					NetworkPolicies(testNamespace).Delete(ctx, policy.Name, metav1.DeleteOptions{})).To(Succeed())
			})

			Expect(hook.callsFor(userMutating, "networkpolicies")).To(BeNumerically(">", 0))
		})
	})

	Describe("the exempt service account matchCondition", func() {
		for _, sa := range []string{exemptWebhookSA, exemptNodeSA, exemptKCSA} {
			It("keeps "+sa+" away from the webhook", func() {
				Expect(listPolicies(sa, metav1.ListOptions{})).To(Succeed())

				Expect(hook.callsBy(sa)).To(Equal(0),
					"gating Calico's own components would deadlock informer bootstrap under failurePolicy: Deny")
			})
		}

		// Paired with the specs above: an expression that matches nothing exempts nothing,
		// which looks like success everywhere else in this suite. These two pin it down.
		It("consults the webhook for a service account whose name is not on the list", func() {
			err := listPolicies(userNearMissName, metav1.ListOptions{})

			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden, got %v", err)
			Expect(hook.callsFor(userNearMissName, "networkpolicies")).To(BeNumerically(">", 0))
		})

		It("consults the webhook for an exempt name in a different namespace", func() {
			err := listPolicies(userNearMissNS, metav1.ListOptions{})

			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden, got %v", err)
			Expect(hook.callsFor(userNearMissNS, "networkpolicies")).To(BeNumerically(">", 0),
				"the exemption names three service accounts in kube-system, not three names anywhere")
		})
	})

	Describe("tier enforcement on reads", func() {
		It("denies an unselectored list and tells the client how to narrow it", func() {
			err := listPolicies(userNoTier, metav1.ListOptions{})

			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden, got %v", err)
			Expect(err.Error()).To(ContainSubstring("--selector "+v3.LabelTier+"="),
				"the deny message is the only place a user learns how to make the request succeed")
			Expect(hook.callsFor(userNoTier, "networkpolicies")).To(BeNumerically(">", 0))
		})

		It("allows an unselectored list by a tier-unrestricted user", func() {
			// The control for the spec above: the same request, denied only for want of
			// tier-unrestricted RBAC.
			Expect(listPolicies(userUnrestricted, metav1.ListOptions{})).To(Succeed())
			Expect(hook.callsFor(userUnrestricted, "networkpolicies")).To(BeNumerically(">", 0),
				"a success the webhook never saw would prove nothing about the unrestricted path")
		})

		It("allows a list scoped to a tier the user may read", func() {
			opts := metav1.ListOptions{LabelSelector: v3.LabelTier + "=" + restrictedTier}

			Expect(listPolicies(userTierScoped, opts)).To(Succeed())
			Expect(hook.callsFor(userTierScoped, "networkpolicies")).To(BeNumerically(">", 0))
		})

		It("authorizes a named policy against the tier it belongs to", func() {
			Expect(getPolicy(userNamedAllowed, labeledPolicy)).To(Succeed())

			err := getPolicy(userNamedDenied, labeledPolicy)
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden, got %v", err)
			Expect(err.Error()).To(ContainSubstring(restrictedTier),
				"the deny names the tier, which can only have come from the resolved policy")
		})

		It("resolves the tier of an unlabelled policy from a live read", func() {
			// The cache has the policy but no tier label, so it reads spec.tier back from the
			// API server. That read is authorized through this very webhook, and only the
			// service account exemption keeps it from recursing.
			err := getPolicy(userUnlabeledDeny, unlabeledPolicy)

			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden, got %v", err)
			Expect(err.Error()).To(ContainSubstring(restrictedTier))
		})
	})

	It("never answers Allowed, so RBAC still gates the request", func() {
		// This user is authorized for the tier but has no permission on networkpolicies at
		// all. An Allowed response would satisfy the whole authorization chain and the list
		// would succeed; NoOpinion leaves RBAC to reject it.
		err := listPolicies(userNoBaseRBAC, metav1.ListOptions{LabelSelector: v3.LabelTier + "=" + restrictedTier})

		Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected RBAC to reject the request, got %v", err)
		// Both authorizers phrase a denial as Forbidden, so distinguish them by the message:
		// only RBAC's names the resource this way, and only tierauth's names a tier.
		Expect(err.Error()).To(ContainSubstring(`cannot list resource "networkpolicies"`),
			"the rejection should be RBAC's, not the webhook's")
		Expect(err.Error()).NotTo(ContainSubstring("in tier"))
		Expect(hook.callsFor(userNoBaseRBAC, "networkpolicies")).To(BeNumerically(">", 0))
	})

	It("caches a denial for unauthorizedTTL", func() {
		hook.setDecider(func(authorizationv1.SubjectAccessReview) authorizationv1.SubjectAccessReviewStatus {
			return authorizationv1.SubjectAccessReviewStatus{Denied: true, Reason: "denied by the test"}
		})
		Expect(listPolicies(userCachedDeny, metav1.ListOptions{})).NotTo(Succeed())

		// Turn permissive. The decision is cached, so this must not take effect at once:
		// spec.tier is mutable, which is what makes this TTL a security parameter.
		hook.clearCalls()
		hook.setDecider(func(authorizationv1.SubjectAccessReview) authorizationv1.SubjectAccessReviewStatus {
			return authorizationv1.SubjectAccessReviewStatus{}
		})

		Expect(listPolicies(userCachedDeny, metav1.ListOptions{})).NotTo(Succeed())
		Expect(hook.callsBy(userCachedDeny)).To(Equal(0), "the denial should have been served from the cache")

		// And must take effect once the entry expires.
		Eventually(func() error {
			return listPolicies(userCachedDeny, metav1.ListOptions{})
		}, 4*unauthorizedTTL, 250*time.Millisecond).Should(Succeed())
		Expect(hook.callsBy(userCachedDeny)).To(BeNumerically(">", 0))
	})
})
