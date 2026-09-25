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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var (
	testClient client.Client
	testCfg    *rest.Config
	testScheme *k8sruntime.Scheme
	testEnvObj *envtest.Environment

	// admissionPoliciesEnabled is true when the API server serves
	// MutatingAdmissionPolicy at v1beta1. Admission tests skip when false.
	admissionPoliciesEnabled bool

	// k8sPoliciesEnabled is true when the API server serves
	// ValidatingAdmissionPolicy. It gates the policies in api/admission/k8s/.
	k8sPoliciesEnabled bool
)

// crdDir returns the path to api/config/crd/ containing Calico CRD YAML files.
func crdDir() string {
	if dir := os.Getenv("CALICO_CRD_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(testutils.FindRepoRoot(), "api", "config", "crd")
}

// admissionDir returns the path to api/admission/ containing MutatingAdmissionPolicy YAML files.
func admissionDir() string {
	return filepath.Join(testutils.FindRepoRoot(), "api", "admission")
}

// k8sAdmissionDir returns the path to api/admission/k8s/.
func k8sAdmissionDir() string {
	return filepath.Join(admissionDir(), "k8s")
}

// envtestSupportsMAP checks if the envtest kube-apiserver binary serves
// MutatingAdmissionPolicy at v1beta1, which K8s 1.34 is the first to do.
func envtestSupportsMAP() bool {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		return false
	}
	bin := filepath.Join(assets, "kube-apiserver")
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return false
	}
	// Output: "Kubernetes v1.35.0"
	ver := strings.TrimSpace(string(out))
	// Extract minor version. Format: "Kubernetes vMAJOR.MINOR.PATCH"
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	// parts[0] ends with the major version after "v", parts[1] is the minor.
	var minor int
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return false
	}
	return minor >= 34
}

// installAdmissionPolicies applies all YAML files in the admission directory to the envtest cluster.
func installAdmissionPolicies(c client.Client) error {
	entries, err := os.ReadDir(admissionDir())
	if err != nil {
		return fmt.Errorf("reading admission dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(admissionDir(), entry.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		// An admission file may contain multiple YAML documents (e.g. a policy
		// and its binding), so decode and create each one. Installing only the
		// first document would, for example, create a ValidatingAdmissionPolicy
		// without its binding, leaving the policy unenforced.
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			obj := &unstructured.Unstructured{}
			if err := dec.Decode(&obj.Object); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("decoding %s: %w", entry.Name(), err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if err := c.Create(context.Background(), obj); err != nil {
				return fmt.Errorf("creating %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

// envtestServesVAP reports whether the API server serves ValidatingAdmissionPolicy.
func envtestServesVAP(cfg *rest.Config) (bool, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("building a discovery client: %w", err)
	}
	resources, err := dc.ServerResourcesForGroupVersion("admissionregistration.k8s.io/v1")
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("listing admissionregistration.k8s.io/v1 resources: %w", err)
	}
	for _, r := range resources.APIResources {
		if r.Kind == "ValidatingAdmissionPolicy" {
			return true, nil
		}
	}
	return false, nil
}

// installK8sAdmissionPolicies applies all YAML files in api/admission/k8s/.
func installK8sAdmissionPolicies(c client.Client) error {
	entries, err := os.ReadDir(k8sAdmissionDir())
	if err != nil {
		return fmt.Errorf("reading admission dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(k8sAdmissionDir(), entry.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			obj := &unstructured.Unstructured{}
			if err := dec.Decode(&obj.Object); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("decoding %s: %w", entry.Name(), err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if err := c.Create(context.Background(), obj); err != nil {
				return fmt.Errorf("creating %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

// grantPodWrites lets authenticated identities write Pods, so impersonated
// clients are refused by admission rather than RBAC.
func grantPodWrites(c client.Client) error {
	ctx := context.Background()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "validation-test-pod-writer"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods", "pods/status"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		}},
	}
	if err := c.Create(ctx, role); err != nil {
		return fmt.Errorf("creating ClusterRole: %w", err)
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "validation-test-pod-writer"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     role.Name,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     "Group",
			Name:     "system:authenticated",
		}},
	}
	if err := c.Create(ctx, binding); err != nil {
		return fmt.Errorf("creating ClusterRoleBinding: %w", err)
	}
	return nil
}

// waitForCRDsReady polls until Calico CRDs are fully usable after admission policy
// installation. The MAPs target NetworkPolicy, so we verify by doing a create+delete
// round-trip rather than just a List (which can succeed before the admission chain is ready).
func waitForCRDsReady(c client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for {
		probe := &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "readiness-probe",
				Namespace: "default",
			},
			Spec: v3.NetworkPolicySpec{Selector: "all()"},
		}
		if err := c.Create(ctx, probe); err == nil {
			_ = c.Delete(ctx, probe)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for CRDs to become ready")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// TestMain spins up a real kube-apiserver process (via controller-runtime's
// envtest package) with our CRDs installed, then runs the tests against it.
// This lets us validate CRD-level validation (CEL rules, OpenAPI schemas, etc.)
// without needing a full cluster. The apiserver is started once before all
// tests and torn down after they complete.
func TestMain(m *testing.M) {
	testEnvObj = &envtest.Environment{
		CRDDirectoryPaths: []string{crdDir()},
	}

	// Older API servers refuse to start with this runtime-config, so leave it
	// off for the ut-validation-min-k8s lane.
	admissionPoliciesEnabled = envtestSupportsMAP()
	if admissionPoliciesEnabled {
		testEnvObj.ControlPlane.GetAPIServer().Configure().
			Set("feature-gates", "MutatingAdmissionPolicy=true").
			Set("runtime-config", "admissionregistration.k8s.io/v1beta1=true").
			Append("enable-admission-plugins", "MutatingAdmissionPolicy")
	}

	cfg, err := testEnvObj.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	code := 1
	defer func() {
		if err := testEnvObj.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
		}
		os.Exit(code)
	}()

	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add client-go scheme: %v\n", err)
		return
	}
	if err := v3.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add calico v3 scheme: %v\n", err)
		return
	}

	testCfg = cfg
	testScheme = scheme

	testClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client: %v\n", err)
		return
	}

	if err := grantPodWrites(testClient); err != nil {
		fmt.Fprintf(os.Stderr, "failed to grant Pod writes to authenticated users: %v\n", err)
		return
	}

	if admissionPoliciesEnabled {
		if err := installAdmissionPolicies(testClient); err != nil {
			fmt.Fprintf(os.Stderr, "failed to install admission policies: %v\n", err)
			return
		}

		// After installing admission policies, the API server may briefly make CRDs
		// unavailable while reloading. Wait for a known CRD to be usable.
		if err := waitForCRDsReady(testClient); err != nil {
			fmt.Fprintf(os.Stderr, "CRDs not ready after admission policy install: %v\n", err)
			return
		}
	}

	k8sPoliciesEnabled, err = envtestServesVAP(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to check whether ValidatingAdmissionPolicy is served: %v\n", err)
		return
	}
	if k8sPoliciesEnabled {
		if err := installK8sAdmissionPolicies(testClient); err != nil {
			fmt.Fprintf(os.Stderr, "failed to install admission policies over Kubernetes resources: %v\n", err)
			return
		}
	}

	code = m.Run()
}
