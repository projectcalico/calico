// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package cluster

import (
	"bytes"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDiagnosticResourcesOmitCredentials(t *testing.T) {
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "example", "namespace": "default", "annotations": map[string]any{"last-applied": "test-secret"}}, "spec": map[string]any{"nodeName": "node-1", "containers": []any{map[string]any{"name": "app", "image": "example/image:v1", "command": []string{"test-secret"}, "args": []string{"--password=test-secret"}, "env": []any{map[string]any{"name": "PASSWORD", "value": "test-secret"}}}}}}
	for _, obj := range []map[string]any{pod, {"kind": "Deployment", "spec": map[string]any{"template": pod}}, {"kind": "CronJob", "spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": pod}}}}, {"kind": "List", "items": []any{pod}}} {
		input, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		output, err := sanitizeDiagnosticResources(input)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output, []byte("test-secret")) {
			t.Fatal("diagnostic export contains credential")
		}
		if !bytes.Contains(output, []byte("example/image:v1")) || !bytes.Contains(output, []byte("node-1")) {
			t.Fatal("diagnostic fields lost")
		}
	}
	if _, err := sanitizeDiagnosticResources([]byte("invalid: [")); err == nil {
		t.Fatal("malformed output accepted")
	}
}
func TestCensorSecretRemovesEmbeddedCopies(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "default", Annotations: map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "test-secret"}}, Data: map[string][]byte{"tls.key": []byte("test-secret"), "tls.crt": []byte("public-cert")}, StringData: map[string]string{"tls.key": "test-secret"}}
	censorSecret(secret)
	if len(secret.Annotations) != 0 || len(secret.StringData) != 0 || string(secret.Data["tls.key"]) != "<censored>" || string(secret.Data["tls.crt"]) != "public-cert" {
		t.Fatal("secret censorship did not protect credentials and preserve public certificate")
	}
}

func TestWorkloadDiagnosticCommandsHaveSanitizers(t *testing.T) {
	commands := kubernetesResourceCmds(t.TempDir())
	for _, resource := range []string{"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "configmaps"} {
		found := false
		for _, command := range commands {
			if command.CmdStr == "kubectl get "+resource+" --all-namespaces -o yaml" {
				found = true
				if command.SanitizeOutput == nil {
					t.Errorf("%s export has no sanitizer", resource)
				}
			}
		}
		if !found {
			t.Errorf("missing workload diagnostic command for %s", resource)
		}
	}
}
