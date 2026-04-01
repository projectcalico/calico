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

package testutils

import (
	"path/filepath"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/client/informers_generated/externalversions"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	libtestutils "github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

// TestEnv wraps an envtest.Environment with pre-built clients for Calico
// controller FV tests. Use NewTestEnv in TestMain to start the environment,
// and call Stop when the tests are done.
type TestEnv struct {
	Env *envtest.Environment

	// RestConfig is the kube-apiserver connection config.
	RestConfig *rest.Config

	// K8sClient is a standard Kubernetes clientset.
	K8sClient *kubernetes.Clientset

	// CalicoClient is the generated Calico API clientset.
	CalicoClient clientset.Interface

	// Client is a controller-runtime client with the Calico and core K8s schemes registered.
	Client ctrlclient.WithWatch
}

// NewTestEnv creates and starts an envtest environment with all Calico CRDs
// loaded. The caller must call Stop() when done (typically deferred in TestMain).
func NewTestEnv() (*TestEnv, error) {
	repoRoot := libtestutils.FindRepoRoot()
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join(repoRoot, "api", "config", "crd"),
			filepath.Join(repoRoot, "libcalico-go", "config", "crd"),
		},
	}

	cfg, err := env.Start()
	if err != nil {
		return nil, err
	}
	defer func() {
		if env != nil {
			env.Stop()
		}
	}()

	// Raise rate limits so test assertions and controllers don't get throttled.
	cfg.QPS = 100
	cfg.Burst = 200

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	calicoClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := v3.AddToScheme(scheme); err != nil {
		return nil, err
	}
	client, err := ctrlclient.NewWithWatch(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	te := &TestEnv{
		Env:          env,
		RestConfig:   cfg,
		K8sClient:    k8sClient,
		CalicoClient: calicoClient,
		Client:       client,
	}
	env = nil // ownership transferred to te; prevent defer from stopping
	return te, nil
}

// NewCalicoInformerFactory creates a shared informer factory for Calico resources
// backed by this environment's API server.
func (te *TestEnv) NewCalicoInformerFactory() externalversions.SharedInformerFactory {
	return externalversions.NewSharedInformerFactory(te.CalicoClient, 0)
}

// Stop tears down the envtest environment.
func (te *TestEnv) Stop() error {
	return te.Env.Stop()
}
