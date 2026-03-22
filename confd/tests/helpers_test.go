// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	sigyaml "sigs.k8s.io/yaml"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/confd/pkg/backends/calico"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/confd/pkg/run"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
)

var (
	testEnv    *envtest.Environment
	restConfig *rest.Config

	sharedK8sClient    kubernetes.Interface
	sharedCalicoClient client.Interface
)

func TestMain(m *testing.M) {
	// Set NODENAME early so package-level vars pick it up.
	os.Setenv("NODENAME", "kube-master")
	template.NodeName = "kube-master"
	calico.NodeName = "kube-master"

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:       []string{crdDir()},
		ControlPlaneStopTimeout: 2 * time.Second,
	}
	// Configure service CIDRs to match the clusterIPs used in test resources.
	testEnv.ControlPlane.GetAPIServer().Configure().
		Append("service-cluster-ip-range", "10.101.0.0/16,fd00:96::/112")

	var err error
	restConfig, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	os.Setenv("DATASTORE_TYPE", "kubernetes")
	os.Setenv("KUBECONFIG", writeKubeconfig(restConfig))

	sharedK8sClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create K8s client: %v\n", err)
		os.Exit(1)
	}
	sharedCalicoClient, err = client.NewFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create Calico client: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
	}
	os.Exit(code)
}

// crdDir finds the Calico CRD directory by walking up from the current directory.
// Supports CALICO_CRD_DIR env override for CI environments.
func crdDir() string {
	if dir := os.Getenv("CALICO_CRD_DIR"); dir != "" {
		return dir
	}
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(gomod); err == nil {
			if bytes.Contains(data, []byte("module github.com/projectcalico/calico\n")) ||
				bytes.Contains(data, []byte("module github.com/projectcalico/calico\r\n")) {
				return filepath.Join(dir, "api", "config", "crd")
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find repo root with go.mod")
		}
		dir = parent
	}
}

// writeKubeconfig writes a kubeconfig file for the envtest API server and
// returns the path. Needed because the Calico client reads KUBECONFIG to
// configure its backend syncer.
func writeKubeconfig(cfg *rest.Config) string {
	kubeconfig := clientcmdapi.NewConfig()
	kubeconfig.Clusters["test"] = &clientcmdapi.Cluster{
		Server:                   cfg.Host,
		CertificateAuthorityData: cfg.CAData,
	}
	kubeconfig.AuthInfos["test"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: cfg.CertData,
		ClientKeyData:         cfg.KeyData,
	}
	kubeconfig.Contexts["test"] = &clientcmdapi.Context{
		Cluster:  "test",
		AuthInfo: "test",
	}
	kubeconfig.CurrentContext = "test"

	f, err := os.CreateTemp("", "confd-test-kubeconfig-*")
	if err != nil {
		panic(fmt.Sprintf("creating kubeconfig temp file: %v", err))
	}
	f.Close()
	if err := clientcmd.WriteToFile(*kubeconfig, f.Name()); err != nil {
		panic(fmt.Sprintf("writing kubeconfig: %v", err))
	}
	return f.Name()
}

func objectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

// applyResources reads a multi-document YAML file and creates each resource.
// It returns a cleanup function that deletes/reverts everything that was created,
// in reverse order. The cleanup function uses t.Logf (not require) so it always
// runs to completion.
//
// For Calico Nodes in KDD mode, it first creates the underlying K8s Node, then
// updates it with Calico-specific BGP configuration. The cleanup function reverts
// the Node spec to its pre-test state rather than deleting it.
func applyResources(t *testing.T, cc client.Interface, k8s kubernetes.Interface, path string) func() {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading %s", path)

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	ctx := context.Background()

	// Track created resources for cleanup. Each entry is a func that
	// deletes or reverts one resource.
	var cleanups []func()

	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err, "decoding YAML from %s", path)
		}
		if raw == nil {
			continue
		}

		kind, _ := raw["kind"].(string)

		// Use sigs.k8s.io/yaml to re-encode because it converts YAML-native
		// types (e.g., boolean label values) to their string equivalents,
		// which standard json.Marshal does not.
		jsonData, err := sigyaml.Marshal(raw)
		require.NoError(t, err)

		switch kind {
		case "Node":
			var calicoNode internalapi.Node
			require.NoError(t, sigyaml.Unmarshal(jsonData, &calicoNode))

			// Create the underlying K8s Node if it doesn't already exist.
			k8sNode := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: calicoNode.Name,
					Labels: map[string]string{
						"kubernetes.io/arch":     "amd64",
						"kubernetes.io/os":       "linux",
						"kubernetes.io/hostname": calicoNode.Name,
					},
				},
			}
			createdK8sNode := false
			if _, createErr := k8s.CoreV1().Nodes().Create(ctx, k8sNode, metav1.CreateOptions{}); createErr == nil {
				createdK8sNode = true
			}

			// Get the existing Calico node, save its spec for revert, then update.
			existing, getErr := cc.Nodes().Get(ctx, calicoNode.Name, options.GetOptions{})
			require.NoError(t, getErr, "getting Calico Node %s", calicoNode.Name)
			savedSpec := existing.Spec
			savedLabels := make(map[string]string)
			for k, v := range existing.Labels {
				savedLabels[k] = v
			}

			existing.Spec = calicoNode.Spec
			if calicoNode.Labels != nil {
				for k, v := range calicoNode.Labels {
					existing.Labels[k] = v
				}
			}
			_, err = cc.Nodes().Update(ctx, existing, options.SetOptions{})
			require.NoError(t, err, "updating Calico Node %s", calicoNode.Name)

			nodeName := calicoNode.Name
			cleanups = append(cleanups, func() {
				// Revert the Calico Node spec to pre-test state.
				node, getErr := cc.Nodes().Get(ctx, nodeName, options.GetOptions{})
				if getErr != nil {
					t.Logf("cleanup: failed to get Node %s for revert: %v", nodeName, getErr)
					return
				}
				node.Spec = savedSpec
				node.Labels = savedLabels
				if _, err := cc.Nodes().Update(ctx, node, options.SetOptions{}); err != nil {
					t.Logf("cleanup: failed to revert Node %s: %v", nodeName, err)
				}
				if createdK8sNode {
					if err := k8s.CoreV1().Nodes().Delete(ctx, nodeName, metav1.DeleteOptions{}); err != nil {
						t.Logf("cleanup: failed to delete K8s Node %s: %v", nodeName, err)
					}
				}
			})

		case "BGPConfiguration":
			var obj apiv3.BGPConfiguration
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			_, err = cc.BGPConfigurations().Create(ctx, &obj, options.SetOptions{})
			require.NoError(t, err, "creating BGPConfiguration %s from %s", obj.Name, path)
			name := obj.Name
			cleanups = append(cleanups, func() {
				if _, err := cc.BGPConfigurations().Delete(ctx, name, options.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete BGPConfiguration %s: %v", name, err)
				}
			})

		case "IPPool":
			var obj apiv3.IPPool
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			_, err = cc.IPPools().Create(ctx, &obj, options.SetOptions{})
			require.NoError(t, err, "creating IPPool %s from %s", obj.Name, path)
			name := obj.Name
			cleanups = append(cleanups, func() {
				if _, err := cc.IPPools().Delete(ctx, name, options.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete IPPool %s: %v", name, err)
				}
			})

		case "BGPPeer":
			var obj apiv3.BGPPeer
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			_, err = cc.BGPPeers().Create(ctx, &obj, options.SetOptions{})
			require.NoError(t, err, "creating BGPPeer %s from %s", obj.Name, path)
			name := obj.Name
			cleanups = append(cleanups, func() {
				if _, err := cc.BGPPeers().Delete(ctx, name, options.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete BGPPeer %s: %v", name, err)
				}
			})

		case "BGPFilter":
			var obj apiv3.BGPFilter
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			_, err = cc.BGPFilter().Create(ctx, &obj, options.SetOptions{})
			require.NoError(t, err, "creating BGPFilter %s from %s", obj.Name, path)
			name := obj.Name
			cleanups = append(cleanups, func() {
				if _, err := cc.BGPFilter().Delete(ctx, name, options.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete BGPFilter %s: %v", name, err)
				}
			})

		case "Service":
			var obj corev1.Service
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			if obj.Namespace == "" {
				obj.Namespace = "default"
			}
			_, err = k8s.CoreV1().Services(obj.Namespace).Create(ctx, &obj, metav1.CreateOptions{})
			require.NoError(t, err, "creating Service %s from %s", obj.Name, path)
			name, ns := obj.Name, obj.Namespace
			cleanups = append(cleanups, func() {
				if err := k8s.CoreV1().Services(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete Service %s: %v", name, err)
				}
			})

		case "Endpoints":
			var obj corev1.Endpoints
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			if obj.Namespace == "" {
				obj.Namespace = "default"
			}
			_, err = k8s.CoreV1().Endpoints(obj.Namespace).Create(ctx, &obj, metav1.CreateOptions{})
			require.NoError(t, err, "creating Endpoints %s from %s", obj.Name, path)
			name, ns := obj.Name, obj.Namespace
			cleanups = append(cleanups, func() {
				if err := k8s.CoreV1().Endpoints(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete Endpoints %s: %v", name, err)
				}
			})

		case "EndpointSlice":
			var obj discoveryv1.EndpointSlice
			require.NoError(t, sigyaml.Unmarshal(jsonData, &obj))
			if obj.Namespace == "" {
				obj.Namespace = "default"
			}
			_, err = k8s.DiscoveryV1().EndpointSlices(obj.Namespace).Create(ctx, &obj, metav1.CreateOptions{})
			require.NoError(t, err, "creating EndpointSlice %s from %s", obj.Name, path)
			name, ns := obj.Name, obj.Namespace
			cleanups = append(cleanups, func() {
				if err := k8s.DiscoveryV1().EndpointSlices(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					t.Logf("cleanup: failed to delete EndpointSlice %s: %v", name, err)
				}
			})

		default:
			t.Fatalf("unsupported resource kind %q in %s", kind, path)
		}
	}

	// Return a cleanup function that runs all cleanups in reverse order.
	return func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
}

// createBlockAffinities creates the IPAM block affinities used by mesh tests.
// Returns a cleanup function. Must be called per-test because IPPool deletion
// removes associated affinities.
func createBlockAffinities(t *testing.T, cc client.Interface) func() {
	t.Helper()
	ctx := context.Background()

	affinities := []apiv3.BlockAffinity{
		{ObjectMeta: objectMeta("kube-master-10-0-0-0-30"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "10.0.0.0/30"}},
		{ObjectMeta: objectMeta("kube-master-10-1-0-0-24"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "10.1.0.0/24"}},
		{ObjectMeta: objectMeta("kube-master-10-2-0-1-32"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "10.2.0.1/32"}},
		{ObjectMeta: objectMeta("kube-master-192-168-221-192-26"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "192.168.221.192/26"}},
		{ObjectMeta: objectMeta("kube-master-192-168-221-64-26"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "192.168.221.64/26", State: "confirmed"}},
		{ObjectMeta: objectMeta("kube-master-192-168-221-0-26"), Spec: apiv3.BlockAffinitySpec{Node: "kube-master", CIDR: "192.168.221.0/26", State: "pending"}},
	}
	for _, a := range affinities {
		_, err := cc.BlockAffinities().Create(ctx, &a, options.SetOptions{})
		if err != nil {
			existing, getErr := cc.BlockAffinities().Get(ctx, a.Name, options.GetOptions{})
			require.NoError(t, getErr, "BlockAffinity %s creation failed and get also failed: create err: %v", a.Name, err)
			a.ResourceVersion = existing.ResourceVersion
			_, err = cc.BlockAffinities().Update(ctx, &a, options.SetOptions{})
			require.NoError(t, err, "updating BlockAffinity %s", a.Name)
		}
	}

	// Block affinities are often removed as a side effect of IPPool deletion,
	// so cleanup is best-effort.
	return func() {}
}

// runConfdTest runs a full in-process confd test: sets up a temp confdir, applies
// test resources, runs confd via run.RunWithContext in oneshot mode, and compares
// the output against golden files.
func runConfdTest(t *testing.T, inputYAML, goldenDir string) {
	t.Helper()

	tmpDir := t.TempDir()
	confDir := filepath.Join(tmpDir, "confd")
	outputDir := filepath.Join(confDir, "config")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	srcConfDir := filepath.Join("..", "etc", "calico", "confd")
	copyDir(t, filepath.Join(srcConfDir, "conf.d"), filepath.Join(confDir, "conf.d"))
	copyDir(t, filepath.Join(srcConfDir, "templates"), filepath.Join(confDir, "templates"))
	rewriteDestPaths(t, filepath.Join(confDir, "conf.d"), outputDir)

	// Create block affinities and apply test resources.
	affinityCleanup := createBlockAffinities(t, sharedCalicoClient)
	inputPath := filepath.Join("mock_data", "calicoctl", inputYAML)
	resourceCleanup := applyResources(t, sharedCalicoClient, sharedK8sClient, inputPath)

	// Apply kubectl resources if they exist (Services, EndpointSlices, etc.).
	var kubectlCleanup func()
	kubectlPath := filepath.Join(filepath.Dir(inputPath), "kubectl-input.yaml")
	if _, statErr := os.Stat(kubectlPath); statErr == nil {
		kubectlCleanup = applyResources(t, sharedCalicoClient, sharedK8sClient, kubectlPath)
	}

	t.Cleanup(func() {
		if kubectlCleanup != nil {
			kubectlCleanup()
		}
		resourceCleanup()
		affinityCleanup()
	})

	// Run confd oneshot with a fresh Calico client so its syncer gets a
	// clean snapshot of the current datastore state.
	confdCalicoClient, err := client.NewFromEnv()
	require.NoError(t, err, "creating confd Calico client")

	confdConfig := &config.Config{
		ConfDir:  confDir,
		Onetime:  true,
		SyncOnly: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = run.RunWithContext(
		ctx,
		confdConfig,
		confdCalicoClient,
		sharedK8sClient,
		apiconfig.CalicoAPIConfigSpec{DatastoreType: apiconfig.Kubernetes},
		&syncclientutils.TyphaConfig{},
		nil,
	)
	require.NoError(t, err, "confd RunWithContext")

	compareOutput(t, outputDir, goldenDir)
}

// compareOutput compares the rendered BIRD config files against the golden files.
func compareOutput(t *testing.T, outputDir, goldenDir string) {
	t.Helper()

	goldenFiles := []string{
		"bird.cfg",
		"bird6.cfg",
		"bird_ipam.cfg",
		"bird6_ipam.cfg",
		"bird_aggr.cfg",
		"bird6_aggr.cfg",
	}
	for _, f := range goldenFiles {
		t.Run(f, func(t *testing.T) {
			actualPath := filepath.Join(outputDir, f)
			got, err := os.ReadFile(actualPath)
			require.NoError(t, err, "reading output %s", f)

			expectedPath := filepath.Join("compiled_templates", goldenDir, f)
			want, err := os.ReadFile(expectedPath)
			require.NoError(t, err, "reading golden file %s", expectedPath)

			gotNorm := normalizeBlankLines(string(got))
			wantNorm := normalizeBlankLines(string(want))
			if gotNorm != wantNorm {
				t.Errorf("output mismatch for %s\nexpected: %s\nactual:   %s\n\n--- expected ---\n%s\n\n--- actual ---\n%s",
					f, expectedPath, actualPath, string(want), string(got))
			}
		})
	}
}

// normalizeBlankLines removes blank lines from a string. This matches the
// behavior of the legacy bash tests which use `diff --ignore-blank-lines` to
// compare output. The Go templates occasionally produce trailing blank lines
// that vary depending on template conditionals.
func normalizeBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// copyDir copies all files from src to dst (non-recursive, files only).
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dst, 0755))
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dst, e.Name()), data, 0644))
	}
}

// rewriteDestPaths rewrites the "dest" field in all TOML config files to point
// at the given output directory.
func rewriteDestPaths(t *testing.T, confDDir, outputDir string) {
	t.Helper()
	entries, err := os.ReadDir(confDDir)
	require.NoError(t, err)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		path := filepath.Join(confDDir, e.Name())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		newData := strings.ReplaceAll(string(data), "/etc/calico/confd/config/", outputDir+"/")
		require.NoError(t, os.WriteFile(path, []byte(newData), 0644))
	}
}
