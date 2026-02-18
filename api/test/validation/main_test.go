// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var (
	testClient client.Client
	testEnvObj *envtest.Environment
)

// crdDir returns the path to config/crd/ containing Calico CRD YAML files.
// It walks up from the current working directory to find the api module root.
func crdDir() string {
	if dir := os.Getenv("CALICO_CRD_DIR"); dir != "" {
		return dir
	}
	dir, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintf("cannot get working directory: %v", err))
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(gomod); err == nil {
			if bytes.Contains(data, []byte("module github.com/projectcalico/api\n")) ||
				bytes.Contains(data, []byte("module github.com/projectcalico/api\r\n")) {
				return filepath.Join(dir, "config", "crd")
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("cannot find api module root (go.mod with module github.com/projectcalico/api)")
		}
		dir = parent
	}
}

func TestMain(m *testing.M) {
	testEnvObj = &envtest.Environment{
		CRDDirectoryPaths: []string{crdDir()},
	}

	cfg, err := testEnvObj.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add client-go scheme: %v\n", err)
		testEnvObj.Stop() //nolint:errcheck
		os.Exit(1)
	}
	if err := v3.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add calico v3 scheme: %v\n", err)
		testEnvObj.Stop() //nolint:errcheck
		os.Exit(1)
	}

	testClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client: %v\n", err)
		testEnvObj.Stop() //nolint:errcheck
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnvObj.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
	}

	os.Exit(code)
}
