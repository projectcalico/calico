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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
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

	k8sClientset    kubernetes.Interface
	calicoClient client.Interface
	ctrlClient   ctrlclient.Client

	// Scheme and decoder for deserializing multi-doc YAML test resources into
	// typed Go objects. Registered types: K8s core (Node, Service, Endpoints),
	// discovery (EndpointSlice), and Calico v3 CRDs (BGPConfiguration, IPPool, etc.).
	testScheme  *runtime.Scheme
	testDecoder runtime.Decoder
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

	// Build a scheme with all the types we need to decode from test YAML files.
	testScheme = runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(testScheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add K8s types to scheme: %v\n", err)
		os.Exit(1)
	}
	if err := discoveryv1.AddToScheme(testScheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add discovery types to scheme: %v\n", err)
		os.Exit(1)
	}
	if err := apiv3.AddToScheme(testScheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add Calico v3 types to scheme: %v\n", err)
		os.Exit(1)
	}
	testDecoder = serializer.NewCodecFactory(testScheme).UniversalDeserializer()

	k8sClientset, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create K8s client: %v\n", err)
		os.Exit(1)
	}
	calicoClient, err = client.NewFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create Calico client: %v\n", err)
		os.Exit(1)
	}
	ctrlClient, err = ctrlclient.New(restConfig, ctrlclient.Options{Scheme: testScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create controller-runtime client: %v\n", err)
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
// Resources are decoded using the universal deserializer (registered via testScheme)
// and created via the controller-runtime client for all CRD and K8s types.
//
// Calico Nodes (apiVersion: projectcalico.org/v3, kind: Node) are a special case:
// they don't have scheme registration (internalapi.Node is not a CRD in KDD mode)
// and require a two-step create (K8s Node first, then Calico Node update).
func applyResources(t *testing.T, cc client.Interface, k8s kubernetes.Interface, path string) func() {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading %s", path)

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	ctx := context.Background()

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
		apiVersion, _ := raw["apiVersion"].(string)

		// Re-encode through sigs.k8s.io/yaml which converts YAML-native types
		// (e.g., boolean label values like `routeReflector: true`) to their
		// string equivalents, which standard json.Marshal does not.
		yamlBytes, err := sigyaml.Marshal(raw)
		require.NoError(t, err)

		// Calico Node (projectcalico.org/v3, kind: Node) is not a CRD and has
		// no scheme registration. Handle it with manual decode + two-step create.
		if apiVersion == "projectcalico.org/v3" && kind == "Node" {
			cleanups = append(cleanups, applyCalicoNode(t, cc, k8s, yamlBytes))
			continue
		}

		// All other types: decode via scheme, create via controller-runtime client.
		obj, gvk, decodeErr := testDecoder.Decode(yamlBytes, nil, nil)
		require.NoError(t, decodeErr, "decoding %s/%s from %s", apiVersion, kind, path)

		clientObj, ok := obj.(ctrlclient.Object)
		require.True(t, ok, "decoded object %v does not implement client.Object", gvk)

		// Default namespace for namespaced resources.
		if clientObj.GetNamespace() == "" {
			clientObj.SetNamespace("default")
		}

		err = ctrlClient.Create(ctx, clientObj)
		require.NoError(t, err, "creating %s %s from %s", kind, clientObj.GetName(), path)

		// Capture for cleanup.
		cleanupObj := clientObj.DeepCopyObject().(ctrlclient.Object)
		cleanups = append(cleanups, func() {
			if err := ctrlClient.Delete(ctx, cleanupObj); err != nil {
				t.Logf("cleanup: failed to delete %s %s: %v", cleanupObj.GetObjectKind().GroupVersionKind().Kind, cleanupObj.GetName(), err)
			}
		})
	}

	return func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
}

// applyCalicoNode handles the special case of Calico Node resources, which are
// backed by K8s Node annotations in KDD mode (not a CRD). It creates the
// underlying K8s Node if needed, then updates it with the Calico BGP spec.
// Returns a cleanup function that reverts the Node to its pre-test state.
func applyCalicoNode(t *testing.T, cc client.Interface, k8s kubernetes.Interface, yamlBytes []byte) func() {
	t.Helper()
	ctx := context.Background()

	var calicoNode internalapi.Node
	require.NoError(t, sigyaml.Unmarshal(yamlBytes, &calicoNode))

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

	// Get the existing Calico node, save its state for revert, then update.
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
	_, err := cc.Nodes().Update(ctx, existing, options.SetOptions{})
	require.NoError(t, err, "updating Calico Node %s", calicoNode.Name)

	nodeName := calicoNode.Name
	return func() {
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
	affinityCleanup := createBlockAffinities(t, calicoClient)
	inputPath := filepath.Join("mock_data", "calicoctl", inputYAML)
	resourceCleanup := applyResources(t, calicoClient, k8sClientset, inputPath)

	// Apply kubectl resources if they exist (Services, EndpointSlices, etc.).
	var kubectlCleanup func()
	kubectlPath := filepath.Join(filepath.Dir(inputPath), "kubectl-input.yaml")
	if _, statErr := os.Stat(kubectlPath); statErr == nil {
		kubectlCleanup = applyResources(t, calicoClient, k8sClientset, kubectlPath)
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
		k8sClientset,
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
