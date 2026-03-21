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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/confd/pkg/backends/calico"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/confd/pkg/run"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var (
	testEnv    *envtest.Environment
	restConfig *rest.Config

	// Shared K8s client for all tests.
	sharedK8sClient kubernetes.Interface

	// Shared Calico client for resource setup/cleanup.
	sharedCalicoClient client.Interface
)

func TestMain(m *testing.M) {
	// Set NODENAME early so package-level vars pick it up.
	os.Setenv("NODENAME", "kube-master")
	template.NodeName = "kube-master"
	calico.NodeName = "kube-master"

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:        []string{crdDir()},
		ControlPlaneStopTimeout:  2 * time.Second,
	}

	var err error
	restConfig, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	os.Setenv("DATASTORE_TYPE", "kubernetes")
	os.Setenv("KUBECONFIG", writeKubeconfig(restConfig))

	// Create shared clients from config.
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

// createK8sNodes creates the K8s Node objects needed by the test. In KDD mode,
// Calico Nodes are backed by K8s Nodes, so these must exist before applying
// Calico Node resources.
func createK8sNodes(t *testing.T, k8s kubernetes.Interface) {
	t.Helper()
	ctx := context.Background()
	for _, name := range []string{"kube-master", "kube-node-1", "kube-node-2"} {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"kubernetes.io/arch":     "amd64",
					"kubernetes.io/os":       "linux",
					"kubernetes.io/hostname": name,
				},
			},
		}
		_, err := k8s.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
		require.NoError(t, err, "creating K8s node %s", name)
	}
}

// deleteK8sNodes removes all K8s Node objects.
func deleteK8sNodes(t *testing.T, k8s kubernetes.Interface) {
	t.Helper()
	ctx := context.Background()
	nodes, err := k8s.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(t, err, "listing K8s nodes for cleanup")
	for _, n := range nodes.Items {
		err := k8s.CoreV1().Nodes().Delete(ctx, n.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "deleting K8s node %s", n.Name)
	}
}

// createBlockAffinities creates the IPAM block affinities used by mesh tests.
// Must be called per-test because IPPool deletion removes associated affinities.
func createBlockAffinities(t *testing.T, cc client.Interface) {
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
			// May already exist if IPPool deletion didn't clean it up.
			existing, getErr := cc.BlockAffinities().Get(ctx, a.Name, options.GetOptions{})
			require.NoError(t, getErr, "BlockAffinity %s creation failed and get also failed: create err: %v", a.Name, err)
			a.ResourceVersion = existing.ResourceVersion
			_, err = cc.BlockAffinities().Update(ctx, &a, options.SetOptions{})
			require.NoError(t, err, "updating BlockAffinity %s", a.Name)
		}
	}
}

// crdDir finds the Calico CRD directory by walking up from the current directory.
func crdDir() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(gomod); err == nil {
			if bytes.Contains(data, []byte("module github.com/projectcalico/calico\n")) {
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


// applyResources reads a multi-document YAML file and creates each Calico resource.
// For Nodes in KDD mode, it first creates a K8s Node, then updates it with
// Calico-specific BGP configuration via the Calico client.
func applyResources(t *testing.T, cc client.Interface, k8s kubernetes.Interface, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading %s", path)

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	ctx := context.Background()

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
		jsonData, err := json.Marshal(raw)
		require.NoError(t, err)

		switch kind {
		case "Node":
			// In KDD mode, Calico Nodes are backed by K8s Nodes. We need to
			// create the K8s Node first, then update it with Calico BGP data.
			var calicoNode internalapi.Node
			require.NoError(t, json.Unmarshal(jsonData, &calicoNode))

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
			_, err = k8s.CoreV1().Nodes().Create(ctx, k8sNode, metav1.CreateOptions{})
			if err != nil {
				// May already exist from a previous resource in the same file.
				_, err = k8s.CoreV1().Nodes().Get(ctx, calicoNode.Name, metav1.GetOptions{})
			}
			require.NoError(t, err, "creating K8s Node %s", calicoNode.Name)

			// Get the node to pick up ObjectMeta (ResourceVersion, etc.), then update with Calico BGP data.
			existing, getErr := cc.Nodes().Get(ctx, calicoNode.Name, options.GetOptions{})
			require.NoError(t, getErr, "getting Calico Node %s", calicoNode.Name)
			existing.Spec = calicoNode.Spec
			if calicoNode.Labels != nil {
				for k, v := range calicoNode.Labels {
					existing.Labels[k] = v
				}
			}
			_, err = cc.Nodes().Update(ctx, existing, options.SetOptions{})
			require.NoError(t, err, "updating Calico Node %s", calicoNode.Name)
		case "BGPConfiguration":
			var obj apiv3.BGPConfiguration
			require.NoError(t, json.Unmarshal(jsonData, &obj))
			_, err = cc.BGPConfigurations().Create(ctx, &obj, options.SetOptions{})
		case "IPPool":
			var obj apiv3.IPPool
			require.NoError(t, json.Unmarshal(jsonData, &obj))
			_, err = cc.IPPools().Create(ctx, &obj, options.SetOptions{})
		case "BGPPeer":
			var obj apiv3.BGPPeer
			require.NoError(t, json.Unmarshal(jsonData, &obj))
			_, err = cc.BGPPeers().Create(ctx, &obj, options.SetOptions{})
		case "BGPFilter":
			var obj apiv3.BGPFilter
			require.NoError(t, json.Unmarshal(jsonData, &obj))
			_, err = cc.BGPFilter().Create(ctx, &obj, options.SetOptions{})
		default:
			t.Fatalf("unsupported resource kind %q in %s", kind, path)
		}
		if kind != "Node" {
			require.NoError(t, err, "creating %s from %s", kind, path)
		}
	}
}

// deleteTestResources removes per-test Calico resources (BGPConfig, IPPools, Peers, Filters)
// and clears Calico Node specs, but leaves shared fixtures (K8s nodes, block affinities) intact.
func deleteTestResources(t *testing.T, cc client.Interface) {
	t.Helper()
	ctx := context.Background()

	peers, err := cc.BGPPeers().List(ctx, options.ListOptions{})
	require.NoError(t, err, "listing BGPPeers for cleanup")
	for _, p := range peers.Items {
		_, err := cc.BGPPeers().Delete(ctx, p.Name, options.DeleteOptions{})
		require.NoError(t, err, "deleting BGPPeer %s", p.Name)
	}

	filters, err := cc.BGPFilter().List(ctx, options.ListOptions{})
	require.NoError(t, err, "listing BGPFilters for cleanup")
	for _, f := range filters.Items {
		_, err := cc.BGPFilter().Delete(ctx, f.Name, options.DeleteOptions{})
		require.NoError(t, err, "deleting BGPFilter %s", f.Name)
	}

	pools, err := cc.IPPools().List(ctx, options.ListOptions{})
	require.NoError(t, err, "listing IPPools for cleanup")
	for _, p := range pools.Items {
		_, err := cc.IPPools().Delete(ctx, p.Name, options.DeleteOptions{})
		require.NoError(t, err, "deleting IPPool %s", p.Name)
	}

	configs, err := cc.BGPConfigurations().List(ctx, options.ListOptions{})
	require.NoError(t, err, "listing BGPConfigurations for cleanup")
	for _, c := range configs.Items {
		_, err := cc.BGPConfigurations().Delete(ctx, c.Name, options.DeleteOptions{})
		require.NoError(t, err, "deleting BGPConfiguration %s", c.Name)
	}

	// Block affinities may have already been removed by IPPool deletion.
	affinities, err := cc.BlockAffinities().List(ctx, options.ListOptions{})
	require.NoError(t, err, "listing BlockAffinities for cleanup")
	for _, a := range affinities.Items {
		if _, err := cc.BlockAffinities().Delete(ctx, a.Name, options.DeleteOptions{}); err != nil {
			t.Logf("Warning: failed to delete BlockAffinity %s: %v", a.Name, err)
		}
	}
}

func objectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

func TestTemplateRendering(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"mesh/bgp-export", "mesh/bgp-export/input.yaml", "mesh/bgp-export"},
		{"mesh/ipip-always", "mesh/ipip-always/input.yaml", "mesh/ipip-always"},
		{"mesh/ipip-cross-subnet", "mesh/ipip-cross-subnet/input.yaml", "mesh/ipip-cross-subnet"},
		{"mesh/ipip-off", "mesh/ipip-off/input.yaml", "mesh/ipip-off"},
		{"mesh/vxlan-always", "mesh/vxlan-always/input.yaml", "mesh/vxlan-always"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runConfdTest(t, tc.inputYAML, tc.goldenDir)
		})
	}
}

// runConfdTest runs a full in-process confd test: sets up a temp confdir, applies
// test resources to the envtest API server, runs confd via run.RunWithContext in
// oneshot mode, and compares the output against golden files.
func runConfdTest(t *testing.T, inputYAML, goldenDir string) {
	t.Helper()

	// Set up temp directories for confd.
	tmpDir := t.TempDir()
	confDir := filepath.Join(tmpDir, "confd")
	outputDir := filepath.Join(confDir, "config")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	// Copy conf.d and templates into the temp confdir.
	srcConfDir := filepath.Join("..", "etc", "calico", "confd")
	copyDir(t, filepath.Join(srcConfDir, "conf.d"), filepath.Join(confDir, "conf.d"))
	copyDir(t, filepath.Join(srcConfDir, "templates"), filepath.Join(confDir, "templates"))

	// Rewrite dest paths in TOML configs to point at our temp output dir.
	rewriteDestPaths(t, filepath.Join(confDir, "conf.d"), outputDir)

	// Create all per-test resources: K8s nodes, block affinities, then
	// Calico resources from the test's input.yaml.
	createK8sNodes(t, sharedK8sClient)
	createBlockAffinities(t, sharedCalicoClient)
	inputPath := filepath.Join("mock_data", "calicoctl", inputYAML)
	applyResources(t, sharedCalicoClient, sharedK8sClient, inputPath)
	t.Cleanup(func() {
		deleteTestResources(t, sharedCalicoClient)
		deleteK8sNodes(t, sharedK8sClient)
	})

	// Run confd oneshot. Create a fresh Calico client for confd so its syncer
	// gets a clean view of the current datastore state.
	confdCalicoClient, err := client.NewFromEnv()
	require.NoError(t, err, "creating confd Calico client")

	confdConfig := &config.Config{
		ConfDir:  confDir,
		Onetime:  true,
		SyncOnly: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = run.RunWithContext(ctx, confdConfig, confdCalicoClient, sharedK8sClient, nil)
	require.NoError(t, err, "confd RunWithContext")

	// Compare output files against golden files.
	goldenFiles := []string{
		"bird.cfg", "bird6.cfg",
		"bird_ipam.cfg", "bird6_ipam.cfg",
		"bird_aggr.cfg", "bird6_aggr.cfg",
	}
	for _, f := range goldenFiles {
		t.Run(f, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join(outputDir, f))
			require.NoError(t, err, "reading output %s", f)

			want := readGolden(t, goldenDir, f)
			if normalizeBlankLines(string(got)) != normalizeBlankLines(want) {
				t.Errorf("output mismatch for %s\n\n--- want ---\n%s\n\n--- got ---\n%s", f, want, string(got))
			}
		})
	}
}

func readGolden(t *testing.T, goldenDir, filename string) string {
	t.Helper()
	path := filepath.Join("compiled_templates", goldenDir, filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading golden file %s", path)
	return string(data)
}

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
