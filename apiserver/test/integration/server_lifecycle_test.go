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

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

const (
	authConfigMapNamespace = "kube-system"
	authConfigMapName      = "extension-apiserver-authentication"
	authConfigMapTestKey   = "calico-integration-test"
	serverExitTimeout      = 60 * time.Second

	// watchShutdownTimeout is well under kubelet's default 30s termination grace period.
	watchShutdownTimeout = 15 * time.Second
)

// TestServerSurvivesExtensionAuthConfigMapChange checks that a data change to the extension-apiserver-authentication
// ConfigMap, which kube-apiserver makes when CAs rotate, neither stops RunServer nor breaks requests.
func TestServerSurvivesExtensionAuthConfigMapChange(t *testing.T) {
	apiServer := startTestServer(t, NewTestServerConfig(), nil)
	defer apiServer.stop()

	ctx := context.Background()
	kubeClient := newKubeClient(t)
	err := updateAuthConfigMap(ctx, kubeClient, func(cm *corev1.ConfigMap) {
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[authConfigMapTestKey] = time.Now().String()
	})
	if err != nil {
		t.Fatalf("Updating the %s ConfigMap: %v", authConfigMapName, err)
	}
	t.Cleanup(func() {
		err := updateAuthConfigMap(ctx, kubeClient, func(cm *corev1.ConfigMap) {
			delete(cm.Data, authConfigMapTestKey)
		})
		if err != nil {
			t.Errorf("Restoring the %s ConfigMap: %v", authConfigMapName, err)
		}
	})

	select {
	case <-apiServer.exited:
		t.Fatalf("RunServer returned after the %s ConfigMap changed: %v", authConfigMapName, apiServer.runErr)
	case <-time.After(5 * time.Second):
	}

	if _, err := apiServer.client.ProjectcalicoV3().Tiers().List(ctx, metav1.ListOptions{}); err != nil {
		t.Fatalf("Listing tiers after the %s ConfigMap changed: %v", authConfigMapName, err)
	}
}

// TestRunServerReturnsServerError checks that RunServer returns the generic API server's error, so the process exits
// non-zero. A failing pre-shutdown hook makes the server return an error once it is stopped.
func TestRunServerReturnsServerError(t *testing.T) {
	const hookName = "calico-integration-test-fail"
	apiServer := startTestServer(t, NewTestServerConfig(), func(s *apiserver.ProjectCalicoServer) {
		if err := s.GenericAPIServer.AddPreShutdownHook(hookName, failingPreShutdownHook); err != nil {
			t.Fatalf("Adding the pre-shutdown hook: %v", err)
		}
	})
	apiServer.stop()

	err := apiServer.waitForExit(t, serverExitTimeout)
	if err == nil || !strings.Contains(err.Error(), hookName) {
		t.Fatalf("RunServer returned %v, want the error from the %q hook", err, hookName)
	}
}

// TestRunServerReturnsNilOnStop checks that RunServer returns nil after a clean shutdown, so a server stopped
// without failing exits zero.
func TestRunServerReturnsNilOnStop(t *testing.T) {
	apiServer := startTestServer(t, NewTestServerConfig(), nil)
	apiServer.stop()

	if err := apiServer.waitForExit(t, serverExitTimeout); err != nil {
		t.Fatalf("RunServer returned %v after a clean stop, want nil", err)
	}
}

// TestRunServerEndsOpenWatchesOnStop checks that stopping the server ends open watches. Without that, shutdown
// waits out the HTTP server's shutdown timeout, which is longer than the pod's termination grace period, so kubelet
// kills the pod on every rollout.
func TestRunServerEndsOpenWatchesOnStop(t *testing.T) {
	apiServer := startTestServer(t, NewTestServerConfig(), nil)

	w, err := apiServer.client.ProjectcalicoV3().Tiers().Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		apiServer.stop()
		t.Fatalf("Watching tiers: %v", err)
	}
	defer w.Stop()

	start := time.Now()
	apiServer.stop()
	if err := apiServer.waitForExit(t, watchShutdownTimeout); err != nil {
		t.Fatalf("RunServer returned %v after a clean stop with an open watch, want nil", err)
	}
	t.Logf("RunServer returned %v after the stop with a watch open", time.Since(start))
}

func failingPreShutdownHook() error {
	return errors.New("failing on purpose")
}

// newKubeClient builds a Kubernetes client for the cluster the integration tests run against.
func newKubeClient(t *testing.T) kubernetes.Interface {
	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("Loading KUBECONFIG: %v", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Creating a Kubernetes client: %v", err)
	}
	return client
}

// updateAuthConfigMap applies mutate to the extension-apiserver-authentication ConfigMap and writes it back. It
// retries on conflicts, since kube-apiserver also writes this ConfigMap.
func updateAuthConfigMap(ctx context.Context, client kubernetes.Interface, mutate func(*corev1.ConfigMap)) error {
	configMaps := client.CoreV1().ConfigMaps(authConfigMapNamespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := configMaps.Get(ctx, authConfigMapName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		mutate(cm)
		_, err = configMaps.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}
