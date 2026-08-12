// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package installation_test

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/enterprise/installation"
)

func dockerConfigJSONSecret(name string, auths map[string]any) *corev1.Secret {
	cfg, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		panic(err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: cfg},
	}
}

func mergedAuths(t *testing.T, s *corev1.Secret) map[string]map[string]string {
	t.Helper()
	var cfg struct {
		Auths map[string]map[string]string `json:"auths"`
	}
	if err := json.Unmarshal(s.Data[corev1.DockerConfigJsonKey], &cfg); err != nil {
		t.Fatalf("merged secret is not valid dockerconfigjson: %v", err)
	}
	return cfg.Auths
}

func TestMergeWAFPullSecret_MergesDisjointRegistries(t *testing.T) {
	merged, skipped := installation.MergeWAFPullSecret([]*corev1.Secret{
		dockerConfigJSONSecret("tigera-pull-secret", map[string]any{"quay.io": map[string]string{"auth": "dGlnZXJh"}}),
		dockerConfigJSONSecret("mirror-pull-secret", map[string]any{"registry.example.com": map[string]string{"auth": "bWlycm9y"}}),
	})
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped secrets, got %v", skipped)
	}
	if merged == nil {
		t.Fatal("expected a merged secret")
	}
	if merged.Name != installation.WASMPullSecretName || merged.Namespace != common.CalicoNamespace {
		t.Fatalf("unexpected name/namespace: %s/%s", merged.Namespace, merged.Name)
	}
	if merged.Type != corev1.SecretTypeDockerConfigJson {
		t.Fatalf("unexpected secret type: %s", merged.Type)
	}
	auths := mergedAuths(t, merged)
	if auths["quay.io"]["auth"] != "dGlnZXJh" || auths["registry.example.com"]["auth"] != "bWlycm9y" {
		t.Fatalf("expected auths from both secrets, got %v", auths)
	}
}

func TestMergeWAFPullSecret_FirstSecretWinsOnDuplicateRegistry(t *testing.T) {
	merged, _ := installation.MergeWAFPullSecret([]*corev1.Secret{
		dockerConfigJSONSecret("first", map[string]any{"quay.io": map[string]string{"auth": "Zmlyc3Q="}}),
		dockerConfigJSONSecret("second", map[string]any{"quay.io": map[string]string{"auth": "c2Vjb25k"}}),
	})
	auths := mergedAuths(t, merged)
	if auths["quay.io"]["auth"] != "Zmlyc3Q=" {
		t.Fatalf("expected the first secret's auth to win, got %v", auths)
	}
}

func TestMergeWAFPullSecret_SkipsUnparseableSecrets(t *testing.T) {
	bad := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte("not-json")},
	}
	merged, skipped := installation.MergeWAFPullSecret([]*corev1.Secret{
		bad,
		dockerConfigJSONSecret("good", map[string]any{"quay.io": map[string]string{"auth": "Z29vZA=="}}),
	})
	if len(skipped) != 1 || skipped[0] != "bad" {
		t.Fatalf("expected [bad] skipped, got %v", skipped)
	}
	auths := mergedAuths(t, merged)
	if auths["quay.io"]["auth"] != "Z29vZA==" {
		t.Fatalf("expected the good secret merged, got %v", auths)
	}
}

func TestMergeWAFPullSecret_LegacyDockercfg(t *testing.T) {
	cfg, err := json.Marshal(map[string]any{"registry.example.com": map[string]string{"auth": "bGVnYWN5"}})
	if err != nil {
		t.Fatal(err)
	}
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockercfg,
		Data:       map[string][]byte{corev1.DockerConfigKey: cfg},
	}
	merged, skipped := installation.MergeWAFPullSecret([]*corev1.Secret{legacy})
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped secrets, got %v", skipped)
	}
	auths := mergedAuths(t, merged)
	if auths["registry.example.com"]["auth"] != "bGVnYWN5" {
		t.Fatalf("expected the legacy dockercfg auth merged, got %v", auths)
	}
}

func TestMergeWAFPullSecret_NothingUsableReturnsNil(t *testing.T) {
	bad := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte("not-json")},
	}
	merged, skipped := installation.MergeWAFPullSecret([]*corev1.Secret{bad})
	if merged != nil {
		t.Fatalf("expected nil secret, got %v", merged)
	}
	if len(skipped) != 1 || skipped[0] != "bad" {
		t.Fatalf("expected [bad] skipped, got %v", skipped)
	}
}

func TestMergeWAFPullSecret_DeterministicOutput(t *testing.T) {
	in := []*corev1.Secret{
		dockerConfigJSONSecret("a", map[string]any{"z.example.com": map[string]string{"auth": "eg=="}, "a.example.com": map[string]string{"auth": "YQ=="}}),
		dockerConfigJSONSecret("b", map[string]any{"m.example.com": map[string]string{"auth": "bQ=="}}),
	}
	first, _ := installation.MergeWAFPullSecret(in)
	second, _ := installation.MergeWAFPullSecret(in)
	if string(first.Data[corev1.DockerConfigJsonKey]) != string(second.Data[corev1.DockerConfigJsonKey]) {
		t.Fatal("merged secret bytes must be deterministic across reconciles")
	}
}
