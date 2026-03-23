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
	"net"
	"os"
	"os/exec"
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

// datastoreBackend holds the clients and config for a single datastore backend
// (KDD or etcd). Tests iterate over activeBackends to run against each.
type datastoreBackend struct {
	name            string
	datastoreType   apiconfig.DatastoreType
	datastoreConfig apiconfig.CalicoAPIConfigSpec
	calicoClient    client.Interface

	// KDD-only fields (nil for etcd).
	k8sClientset kubernetes.Interface
	ctrlClient   ctrlclient.Client
	restConfig   *rest.Config
}

var (
	activeBackends []*datastoreBackend

	// Scheme and decoder for deserializing multi-doc YAML test resources into
	// typed Go objects. Registered types: K8s core (Node, Service, Endpoints),
	// discovery (EndpointSlice), and Calico v3 CRDs (BGPConfiguration, IPPool, etc.).
	testScheme  *runtime.Scheme
	testDecoder runtime.Decoder

	// envtest environment (KDD only).
	testEnv *envtest.Environment

	// etcd process (etcd only).
	etcdCmd *exec.Cmd
)

func TestMain(m *testing.M) {
	os.Setenv("NODENAME", "kube-master")
	template.NodeName = "kube-master"
	calico.NodeName = "kube-master"

	// Build a scheme with all the types we need to decode from test YAML files.
	testScheme = runtime.NewScheme()
	must(clientgoscheme.AddToScheme(testScheme), "adding K8s types to scheme")
	must(discoveryv1.AddToScheme(testScheme), "adding discovery types to scheme")
	must(apiv3.AddToScheme(testScheme), "adding Calico v3 types to scheme")
	testDecoder = serializer.NewCodecFactory(testScheme).UniversalDeserializer()

	// Determine which backends to test. Default: both.
	dsType := os.Getenv("DATASTORE_TYPE")
	if dsType == "" || dsType == "kubernetes" {
		activeBackends = append(activeBackends, setupKDD())
	}
	if dsType == "" || dsType == "etcdv3" {
		activeBackends = append(activeBackends, setupEtcd())
	}
	if len(activeBackends) == 0 {
		fmt.Fprintf(os.Stderr, "no backends configured (DATASTORE_TYPE=%q)\n", dsType)
		os.Exit(1)
	}

	code := m.Run()

	// Teardown.
	if testEnv != nil {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
		}
	}
	if etcdCmd != nil {
		etcdCmd.Process.Kill()
		etcdCmd.Wait()
	}
	os.Exit(code)
}

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

// setupKDD starts envtest and creates all KDD clients.
func setupKDD() *datastoreBackend {
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:       []string{crdDir()},
		ControlPlaneStopTimeout: 2 * time.Second,
	}
	testEnv.ControlPlane.GetAPIServer().Configure().
		Append("service-cluster-ip-range", "10.101.0.0/16,fd00:96::/112")

	restCfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	kubeconfigPath := writeKubeconfig(restCfg)
	os.Setenv("DATASTORE_TYPE", "kubernetes")
	os.Setenv("KUBECONFIG", kubeconfigPath)

	datastoreCfg := apiconfig.CalicoAPIConfigSpec{
		DatastoreType: apiconfig.Kubernetes,
		KubeConfig: apiconfig.KubeConfig{
			Kubeconfig: kubeconfigPath,
		},
	}

	k8s, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create K8s client: %v\n", err)
		os.Exit(1)
	}
	cc, err := client.New(apiconfig.CalicoAPIConfig{Spec: datastoreCfg})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create Calico KDD client: %v\n", err)
		os.Exit(1)
	}
	ctrl, err := ctrlclient.New(restCfg, ctrlclient.Options{Scheme: testScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create controller-runtime client: %v\n", err)
		os.Exit(1)
	}

	return &datastoreBackend{
		name:            "kdd",
		datastoreType:   apiconfig.Kubernetes,
		datastoreConfig: datastoreCfg,
		calicoClient:    cc,
		k8sClientset:    k8s,
		ctrlClient:      ctrl,
		restConfig:      restCfg,
	}
}

// setupEtcd starts a standalone etcd process and creates a Calico client.
func setupEtcd() *datastoreBackend {
	// Find the etcd binary from KUBEBUILDER_ASSETS.
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		fmt.Fprintf(os.Stderr, "KUBEBUILDER_ASSETS not set, cannot start etcd\n")
		os.Exit(1)
	}
	etcdBin := filepath.Join(assets, "etcd")

	// Pick a random free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find free port for etcd: %v\n", err)
		os.Exit(1)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	dataDir, err := os.MkdirTemp("", "confd-test-etcd-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create etcd data dir: %v\n", err)
		os.Exit(1)
	}

	etcdCmd = exec.Command(
		etcdBin,
		"--data-dir", dataDir,
		"--listen-client-urls", endpoint,
		"--advertise-client-urls", endpoint,
		"--listen-peer-urls", "http://127.0.0.1:0",
	)
	etcdCmd.Stdout = os.Stderr
	etcdCmd.Stderr = os.Stderr
	if err := etcdCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start etcd: %v\n", err)
		os.Exit(1)
	}

	// Wait for etcd to be ready.
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	datastoreCfg := apiconfig.CalicoAPIConfigSpec{
		DatastoreType: apiconfig.EtcdV3,
		EtcdConfig: apiconfig.EtcdConfig{
			EtcdEndpoints: endpoint,
		},
	}

	cc, err := client.New(apiconfig.CalicoAPIConfig{
		Spec: datastoreCfg,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create Calico etcd client: %v\n", err)
		os.Exit(1)
	}

	return &datastoreBackend{
		name:            "etcd",
		datastoreType:   apiconfig.EtcdV3,
		datastoreConfig: datastoreCfg,
		calicoClient:    cc,
	}
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
// Returns a cleanup function that deletes/reverts everything in reverse order.
//
// Resources are decoded using the universal deserializer for CRD and K8s types.
// Calico Nodes (projectcalico.org/v3, kind: Node) are special: they're not a CRD
// in KDD mode and require a two-step create. In etcd mode they're created directly.
func applyResources(t *testing.T, be *datastoreBackend, path string) func() {
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

		yamlBytes, err := sigyaml.Marshal(raw)
		require.NoError(t, err)

		// Calico Node needs special handling.
		if apiVersion == "projectcalico.org/v3" && kind == "Node" {
			cleanups = append(cleanups, applyCalicoNode(t, be, yamlBytes))
			continue
		}

		// K8s-native resources (Service, Endpoints, EndpointSlice) are only
		// applicable in KDD mode where there's a K8s API server.
		if apiVersion == "v1" && (kind == "Service" || kind == "Endpoints") && be.ctrlClient == nil {
			t.Logf("skipping %s %s (no K8s API in %s mode)", kind, raw["metadata"].(map[string]any)["name"], be.name)
			continue
		}
		if apiVersion == "discovery.k8s.io/v1" && be.ctrlClient == nil {
			t.Logf("skipping %s (no K8s API in %s mode)", kind, be.name)
			continue
		}

		// For CRD types (BGPConfiguration, IPPool, etc.) in etcd mode, use the
		// Calico client since there's no K8s API server.
		if be.ctrlClient == nil {
			cleanups = append(cleanups, applyCalicoResource(t, be.calicoClient, kind, yamlBytes, path))
			continue
		}

		// KDD mode: decode via scheme, create via controller-runtime client.
		obj, gvk, decodeErr := testDecoder.Decode(yamlBytes, nil, nil)
		require.NoError(t, decodeErr, "decoding %s/%s from %s", apiVersion, kind, path)

		clientObj, ok := obj.(ctrlclient.Object)
		require.True(t, ok, "decoded object %v does not implement client.Object", gvk)

		if clientObj.GetNamespace() == "" {
			clientObj.SetNamespace("default")
		}

		err = be.ctrlClient.Create(ctx, clientObj)
		require.NoError(t, err, "creating %s %s from %s", kind, clientObj.GetName(), path)

		cleanupObj := clientObj.DeepCopyObject().(ctrlclient.Object)
		cleanups = append(cleanups, func() {
			if err := be.ctrlClient.Delete(ctx, cleanupObj); err != nil {
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

// applyCalicoResource creates a Calico CRD resource via the Calico clientv3.
// Used in etcd mode where there's no controller-runtime client.
func applyCalicoResource(t *testing.T, cc client.Interface, kind string, yamlBytes []byte, path string) func() {
	t.Helper()
	ctx := context.Background()

	switch kind {
	case "BGPConfiguration":
		var obj apiv3.BGPConfiguration
		require.NoError(t, sigyaml.Unmarshal(yamlBytes, &obj))
		_, err := cc.BGPConfigurations().Create(ctx, &obj, options.SetOptions{})
		require.NoError(t, err, "creating BGPConfiguration %s from %s", obj.Name, path)
		name := obj.Name
		return func() {
			if _, err := cc.BGPConfigurations().Delete(ctx, name, options.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete BGPConfiguration %s: %v", name, err)
			}
		}
	case "IPPool":
		var obj apiv3.IPPool
		require.NoError(t, sigyaml.Unmarshal(yamlBytes, &obj))
		_, err := cc.IPPools().Create(ctx, &obj, options.SetOptions{})
		require.NoError(t, err, "creating IPPool %s from %s", obj.Name, path)
		name := obj.Name
		return func() {
			if _, err := cc.IPPools().Delete(ctx, name, options.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete IPPool %s: %v", name, err)
			}
		}
	case "BGPPeer":
		var obj apiv3.BGPPeer
		require.NoError(t, sigyaml.Unmarshal(yamlBytes, &obj))
		_, err := cc.BGPPeers().Create(ctx, &obj, options.SetOptions{})
		require.NoError(t, err, "creating BGPPeer %s from %s", obj.Name, path)
		name := obj.Name
		return func() {
			if _, err := cc.BGPPeers().Delete(ctx, name, options.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete BGPPeer %s: %v", name, err)
			}
		}
	case "BGPFilter":
		var obj apiv3.BGPFilter
		require.NoError(t, sigyaml.Unmarshal(yamlBytes, &obj))
		_, err := cc.BGPFilter().Create(ctx, &obj, options.SetOptions{})
		require.NoError(t, err, "creating BGPFilter %s from %s", obj.Name, path)
		name := obj.Name
		return func() {
			if _, err := cc.BGPFilter().Delete(ctx, name, options.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete BGPFilter %s: %v", name, err)
			}
		}
	default:
		t.Fatalf("unsupported Calico resource kind %q in %s", kind, path)
		return nil
	}
}

// applyCalicoNode handles the special case of Calico Node resources.
// In KDD mode: creates K8s Node, then updates with Calico BGP spec.
// In etcd mode: creates Calico Node directly.
// Returns a cleanup function that reverts/deletes the Node.
func applyCalicoNode(t *testing.T, be *datastoreBackend, yamlBytes []byte) func() {
	t.Helper()
	ctx := context.Background()

	var calicoNode internalapi.Node
	require.NoError(t, sigyaml.Unmarshal(yamlBytes, &calicoNode))

	if be.datastoreType == apiconfig.EtcdV3 {
		// etcd mode: create Node directly via Calico client.
		_, err := be.calicoClient.Nodes().Create(ctx, &calicoNode, options.SetOptions{})
		require.NoError(t, err, "creating Calico Node %s", calicoNode.Name)
		nodeName := calicoNode.Name
		return func() {
			if _, err := be.calicoClient.Nodes().Delete(ctx, nodeName, options.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete Node %s: %v", nodeName, err)
			}
		}
	}

	// KDD mode: create K8s Node first, then update with Calico BGP data.
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
	if _, createErr := be.k8sClientset.CoreV1().Nodes().Create(ctx, k8sNode, metav1.CreateOptions{}); createErr == nil {
		createdK8sNode = true
	}

	existing, getErr := be.calicoClient.Nodes().Get(ctx, calicoNode.Name, options.GetOptions{})
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
	_, err := be.calicoClient.Nodes().Update(ctx, existing, options.SetOptions{})
	require.NoError(t, err, "updating Calico Node %s", calicoNode.Name)

	nodeName := calicoNode.Name
	return func() {
		node, getErr := be.calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
		if getErr != nil {
			t.Logf("cleanup: failed to get Node %s for revert: %v", nodeName, getErr)
			return
		}
		node.Spec = savedSpec
		node.Labels = savedLabels
		if _, err := be.calicoClient.Nodes().Update(ctx, node, options.SetOptions{}); err != nil {
			t.Logf("cleanup: failed to revert Node %s: %v", nodeName, err)
		}
		if createdK8sNode {
			if err := be.k8sClientset.CoreV1().Nodes().Delete(ctx, nodeName, metav1.DeleteOptions{}); err != nil {
				t.Logf("cleanup: failed to delete K8s Node %s: %v", nodeName, err)
			}
		}
	}
}

// createBlockAffinities creates the IPAM block affinities used by mesh tests.
// Returns a cleanup function.
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

	return func() {}
}

// runConfdTest runs a full in-process confd test against the given backend.
func runConfdTest(t *testing.T, be *datastoreBackend, inputYAML, goldenDir string) {
	t.Helper()

	tmpDir := t.TempDir()
	confDir := filepath.Join(tmpDir, "confd")
	outputDir := filepath.Join(confDir, "config")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	srcConfDir := filepath.Join("..", "etc", "calico", "confd")
	copyDir(t, filepath.Join(srcConfDir, "conf.d"), filepath.Join(confDir, "conf.d"))
	copyDir(t, filepath.Join(srcConfDir, "templates"), filepath.Join(confDir, "templates"))
	rewriteDestPaths(t, filepath.Join(confDir, "conf.d"), outputDir)

	affinityCleanup := createBlockAffinities(t, be.calicoClient)
	inputPath := filepath.Join("mock_data", "calicoctl", inputYAML)
	resourceCleanup := applyResources(t, be, inputPath)

	var kubectlCleanup func()
	kubectlPath := filepath.Join(filepath.Dir(inputPath), "kubectl-input.yaml")
	if _, statErr := os.Stat(kubectlPath); statErr == nil {
		kubectlCleanup = applyResources(t, be, kubectlPath)
	}

	t.Cleanup(func() {
		if kubectlCleanup != nil {
			kubectlCleanup()
		}
		resourceCleanup()
		affinityCleanup()
	})

	// Create a fresh Calico client for confd so its syncer gets a clean snapshot.
	confdCalicoClient, err := client.New(apiconfig.CalicoAPIConfig{Spec: be.datastoreConfig})
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
		be.k8sClientset,
		be.datastoreConfig,
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
