// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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

package apiconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func TestNewCalicoAPIConfig(t *testing.T) {
	c := NewCalicoAPIConfig()
	if c.Kind != KindCalicoAPIConfig {
		t.Errorf("Kind = %q, want %q", c.Kind, KindCalicoAPIConfig)
	}
	if c.APIVersion != apiv3.GroupVersionCurrent {
		t.Errorf("APIVersion = %q, want %q", c.APIVersion, apiv3.GroupVersionCurrent)
	}
}

func TestLoadClientConfigFromBytes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	kubeconfigPath := filepath.Join(home, ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kubeconfigPath, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("explicit kubernetes datastore", func(t *testing.T) {
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  datastoreType: kubernetes
  kubeconfig: /etc/kubeconfig
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != Kubernetes {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, Kubernetes)
		}
		if c.Spec.Kubeconfig != "/etc/kubeconfig" {
			t.Errorf("Kubeconfig = %q", c.Spec.Kubeconfig)
		}
	})

	t.Run("explicit etcdv3 datastore", func(t *testing.T) {
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  datastoreType: etcdv3
  etcdEndpoints: https://127.0.0.1:2379
  etcdUsername: user
  etcdPassword: pass
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != EtcdV3 {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, EtcdV3)
		}
		if c.Spec.EtcdEndpoints != "https://127.0.0.1:2379" || c.Spec.EtcdUsername != "user" || c.Spec.EtcdPassword != "pass" {
			t.Errorf("etcd fields not loaded: %+v", c.Spec.EtcdConfig)
		}
	})

	t.Run("detect etcdv3 from endpoints", func(t *testing.T) {
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  etcdEndpoints: https://127.0.0.1:2379
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != EtcdV3 {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, EtcdV3)
		}
	})

	t.Run("default to kubernetes and fill kubeconfig from HOME", func(t *testing.T) {
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec: {}
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != Kubernetes {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, Kubernetes)
		}
		if c.Spec.Kubeconfig != kubeconfigPath {
			t.Errorf("Kubeconfig = %q, want %q", c.Spec.Kubeconfig, kubeconfigPath)
		}
	})

	t.Run("endpoint configured disables kubeconfig default", func(t *testing.T) {
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  k8sAPIEndpoint: https://1.2.3.4:6443
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != Kubernetes {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, Kubernetes)
		}
		if c.Spec.Kubeconfig != "" {
			t.Errorf("Kubeconfig = %q, want empty", c.Spec.Kubeconfig)
		}
	})

	t.Run("no home directory leaves kubeconfig blank", func(t *testing.T) {
		t.Setenv("HOME", "")
		c, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec: {}
`, apiv3.GroupVersionCurrent)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.Kubeconfig != "" {
			t.Errorf("Kubeconfig = %q, want empty", c.Spec.Kubeconfig)
		}
	})

	t.Run("unknown APIVersion is rejected", func(t *testing.T) {
		_, err := LoadClientConfigFromBytes([]byte(`
apiVersion: projectcalico.org/v1
kind: CalicoAPIConfig
spec:
  datastoreType: kubernetes
`))
		if err == nil || !strings.Contains(err.Error(), "unknown APIVersion") {
			t.Errorf("expected APIVersion error, got %v", err)
		}
	})

	t.Run("wrong kind is rejected", func(t *testing.T) {
		_, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: KubeControllersConfiguration
spec:
  datastoreType: kubernetes
`, apiv3.GroupVersionCurrent)))
		if err == nil || !strings.Contains(err.Error(), "expected kind") {
			t.Errorf("expected kind error, got %v", err)
		}
	})

	t.Run("unknown field is rejected", func(t *testing.T) {
		_, err := LoadClientConfigFromBytes([]byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  datastoreType: kubernetes
  bogusField: true
`, apiv3.GroupVersionCurrent)))
		if err == nil {
			t.Error("expected error for unknown field")
		}
	})

	t.Run("malformed YAML is rejected", func(t *testing.T) {
		_, err := LoadClientConfigFromBytes([]byte("\t- not: [valid"))
		if err == nil || !strings.Contains(err.Error(), "failed to parse") {
			t.Errorf("expected parse error, got %v", err)
		}
	})
}

func TestLoadClientConfigFromFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("valid file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "calico.kubeconfig")
		contents := []byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  datastoreType: etcdv3
  etcdEndpoints: https://127.0.0.1:2379
`, apiv3.GroupVersionCurrent))
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := LoadClientConfigFromFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != EtcdV3 {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, EtcdV3)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadClientConfigFromFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("syntax error mentions the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte("\t- not: [valid"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadClientConfigFromFile(path)
		if err == nil || !strings.Contains(err.Error(), "bad.yaml") {
			t.Errorf("expected error mentioning file name, got %v", err)
		}
	})
}

func TestLoadClientConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("routes to file when filename given", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "calico.kubeconfig")
		contents := []byte(fmt.Sprintf(`
apiVersion: %s
kind: CalicoAPIConfig
spec:
  datastoreType: etcdv3
`, apiv3.GroupVersionCurrent))
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := LoadClientConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != EtcdV3 {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, EtcdV3)
		}
	})

	t.Run("routes to environment when filename empty", func(t *testing.T) {
		t.Setenv("CALICO_DATASTORE_TYPE", "etcdv3")
		t.Setenv("CALICO_ETCD_ENDPOINTS", "https://127.0.0.1:2379")
		c, err := LoadClientConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != EtcdV3 {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, EtcdV3)
		}
		if c.Spec.EtcdEndpoints != "https://127.0.0.1:2379" {
			t.Errorf("EtcdEndpoints = %q", c.Spec.EtcdEndpoints)
		}
	})
}

func TestLoadClientConfigFromEnvironment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("kubernetes fields from env", func(t *testing.T) {
		t.Setenv("CALICO_DATASTORE_TYPE", "kubernetes")
		t.Setenv("CALICO_K8S_API_ENDPOINT", "https://1.2.3.4:6443")
		t.Setenv("CALICO_K8S_INSECURE_SKIP_TLS_VERIFY", "true")
		t.Setenv("CALICO_K8S_CLIENT_QPS", "10")
		c, err := LoadClientConfigFromEnvironment()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Spec.DatastoreType != Kubernetes {
			t.Errorf("DatastoreType = %q, want %q", c.Spec.DatastoreType, Kubernetes)
		}
		if c.Spec.K8sAPIEndpoint != "https://1.2.3.4:6443" {
			t.Errorf("K8sAPIEndpoint = %q", c.Spec.K8sAPIEndpoint)
		}
		if !c.Spec.K8sInsecureSkipTLSVerify {
			t.Error("K8sInsecureSkipTLSVerify = false, want true")
		}
		if c.Spec.K8sClientQPS != 10 {
			t.Errorf("K8sClientQPS = %v, want 10", c.Spec.K8sClientQPS)
		}
	})

	t.Run("invalid bool env var is an error", func(t *testing.T) {
		t.Setenv("CALICO_DATASTORE_TYPE", "kubernetes")
		t.Setenv("CALICO_K8S_INSECURE_SKIP_TLS_VERIFY", "maybe")
		if _, err := LoadClientConfigFromEnvironment(); err == nil {
			t.Error("expected error for invalid bool")
		}
	})
}
