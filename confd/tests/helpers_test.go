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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
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

	"github.com/projectcalico/calico/confd/pkg/backends/calico"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/confd/pkg/run"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	backendapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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

	// updateGoldenFiles, when true, overwrites golden files with actual output
	// instead of failing on mismatch. Set via UPDATE_EXPECTED_DATA=true.
	updateGoldenFiles = os.Getenv("UPDATE_EXPECTED_DATA") == "true"

	// calicoResourceHandlers maps Calico CRD kinds to their create/cleanup
	// functions for etcd-mode tests. Populated in init(); downstream forks
	// can register additional kinds from init() in a separate _test.go file.
	calicoResourceHandlers = map[string]calicoResourceApplier{}
)

func TestMain(m *testing.M) {
	must(os.Setenv("NODENAME", "kube-master"), "setting NODENAME")
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
		_ = etcdCmd.Process.Kill()
		_ = etcdCmd.Wait()
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

	// Raise QPS and Burst from the defaults (5 / 10) so that test
	// setup and teardown (which do many small API calls) are not
	// throttled by the client-side rate limiter.
	restCfg.QPS = 100
	restCfg.Burst = 200

	kubeconfigPath := writeKubeconfig(restCfg)
	must(os.Setenv("DATASTORE_TYPE", "kubernetes"), "setting DATASTORE_TYPE")
	must(os.Setenv("KUBECONFIG", kubeconfigPath), "setting KUBECONFIG")

	datastoreCfg := apiconfig.CalicoAPIConfigSpec{
		DatastoreType: apiconfig.Kubernetes,
		KubeConfig: apiconfig.KubeConfig{
			Kubeconfig:     kubeconfigPath,
			K8sClientQPS:   100,
			K8sClientBurst: 200,
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
	_ = listener.Close()

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
	ready := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		fmt.Fprintf(os.Stderr, "etcd did not become ready on %s\n", endpoint)
		os.Exit(1)
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
	_ = f.Close()
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

		isNamespaced, nsErr := be.ctrlClient.IsObjectNamespaced(clientObj)
		require.NoError(t, nsErr, "checking if %v is namespaced", gvk)
		if isNamespaced && clientObj.GetNamespace() == "" {
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

// calicoResourceApplier creates a Calico resource via the clientv3 and returns
// a cleanup function. Used by applyCalicoResource for extensibility.
type calicoResourceApplier func(t *testing.T, cc client.Interface, yamlBytes []byte, path string) func()

func init() {
	calicoResourceHandlers["BGPConfiguration"] = applyCalicoBGPConfiguration
	calicoResourceHandlers["IPPool"] = applyCalicoIPPool
	calicoResourceHandlers["BGPPeer"] = applyCalicoBGPPeer
	calicoResourceHandlers["BGPFilter"] = applyCalicoBGPFilter
}

// applyCalicoResource creates a Calico CRD resource via the Calico clientv3.
// Used in etcd mode where there's no controller-runtime client. Handlers are
// registered in calicoResourceHandlers; downstream forks can add more.
func applyCalicoResource(t *testing.T, cc client.Interface, kind string, yamlBytes []byte, path string) func() {
	t.Helper()
	handler, ok := calicoResourceHandlers[kind]
	if !ok {
		t.Fatalf("unsupported Calico resource kind %q in %s", kind, path)
		return nil
	}
	return handler(t, cc, yamlBytes, path)
}

func applyCalicoBGPConfiguration(t *testing.T, cc client.Interface, yamlBytes []byte, path string) func() {
	t.Helper()
	ctx := context.Background()
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
}

func applyCalicoIPPool(t *testing.T, cc client.Interface, yamlBytes []byte, path string) func() {
	t.Helper()
	ctx := context.Background()
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
}

func applyCalicoBGPPeer(t *testing.T, cc client.Interface, yamlBytes []byte, path string) func() {
	t.Helper()
	ctx := context.Background()
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
}

func applyCalicoBGPFilter(t *testing.T, cc client.Interface, yamlBytes []byte, path string) func() {
	t.Helper()
	ctx := context.Background()
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

// waitForResources polls the Calico client until all CRD resources from the
// input YAML are visible via List. Under CI load, the envtest API server can
// briefly return stale list results after a Create.
func waitForResources(t *testing.T, cc client.Interface, inputPath string) {
	t.Helper()

	data, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	expected := countResourcesByKind(data)
	ctx := context.Background()
	listCount := map[string]func() int{
		"BGPPeer":          func() int { l, _ := cc.BGPPeers().List(ctx, options.ListOptions{}); return len(l.Items) },
		"BGPConfiguration": func() int { l, _ := cc.BGPConfigurations().List(ctx, options.ListOptions{}); return len(l.Items) },
		"BGPFilter":        func() int { l, _ := cc.BGPFilter().List(ctx, options.ListOptions{}); return len(l.Items) },
		"IPPool":           func() int { l, _ := cc.IPPools().List(ctx, options.ListOptions{}); return len(l.Items) },
	}

	require.Eventually(t, func() bool {
		for kind, want := range expected {
			if counter, ok := listCount[kind]; ok && counter() < want {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond, "timed out waiting for resources to be visible via Calico client")
}

func countResourcesByKind(data []byte) map[string]int {
	counts := map[string]int{}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			break
		}
		if kind, _ := raw["kind"].(string); kind != "" {
			counts[kind]++
		}
	}
	return counts
}

// blockAffinityEntry defines a block affinity for test setup.
type blockAffinityEntry struct {
	cidr  string
	host  string
	state string // "" for implicitly confirmed, "confirmed", "pending"
}

var standardBlockAffinities = []blockAffinityEntry{
	{"10.0.0.0/30", "kube-master", ""},
	{"10.1.0.0/24", "kube-master", ""},
	{"10.2.0.1/32", "kube-master", ""},
	{"192.168.221.192/26", "kube-master", ""},
	{"192.168.221.64/26", "kube-master", "confirmed"},
	{"192.168.221.0/26", "kube-master", "pending"},
}

// createBlockAffinities creates the IPAM block affinities used by mesh tests.
// In KDD mode, creates via the BlockAffinities API.
// In etcd mode, writes raw v2 IPAM keys directly to etcd (the BGP syncer
// watches these v2 paths, not the v3 BlockAffinity CRD paths).
func createBlockAffinities(t *testing.T, be *datastoreBackend) func() {
	t.Helper()
	ctx := context.Background()

	if be.datastoreType == apiconfig.EtcdV3 {
		// In etcd mode, write raw v2 IPAM block entries that the confd syncer watches.
		// These match the format in mock_data/etcd/block.
		type backendAccessor interface {
			Backend() backendapi.Client
		}
		bc := be.calicoClient.(backendAccessor).Backend()
		for _, a := range standardBlockAffinities {
			_, err := bc.Apply(ctx, &model.KVPair{
				Key: model.BlockAffinityKey{
					CIDR: netip.MustParsePrefix(a.cidr),
					Host: a.host,
				},
				Value: &model.BlockAffinity{
					State: model.BlockAffinityState(a.state),
				},
			})
			require.NoError(t, err, "creating block affinity %s on %s", a.cidr, a.host)
		}
		return func() {
			for _, a := range standardBlockAffinities {
				_, _ = bc.Delete(ctx, model.BlockAffinityKey{
					CIDR: netip.MustParsePrefix(a.cidr),
					Host: a.host,
				}, "")
			}
		}
	}

	// KDD mode: use the BlockAffinities API.
	affinities := make([]apiv3.BlockAffinity, 0, len(standardBlockAffinities))
	for _, a := range standardBlockAffinities {
		name := "kube-master-" + strings.Replace(a.cidr, "/", "-", 1)
		name = strings.ReplaceAll(name, ".", "-")
		affinities = append(affinities, apiv3.BlockAffinity{
			ObjectMeta: objectMeta(name),
			Spec:       apiv3.BlockAffinitySpec{Node: a.host, CIDR: a.cidr, State: apiv3.BlockAffinityState(a.state)},
		})
	}
	for _, a := range affinities {
		_, err := be.calicoClient.BlockAffinities().Create(ctx, &a, options.SetOptions{})
		if err != nil {
			existing, getErr := be.calicoClient.BlockAffinities().Get(ctx, a.Name, options.GetOptions{})
			require.NoError(t, getErr, "BlockAffinity %s creation failed and get also failed: create err: %v", a.Name, err)
			a.ResourceVersion = existing.ResourceVersion
			_, err = be.calicoClient.BlockAffinities().Update(ctx, &a, options.SetOptions{})
			require.NoError(t, err, "updating BlockAffinity %s", a.Name)
		}
	}
	return func() {
		for _, a := range affinities {
			existing, err := be.calicoClient.BlockAffinities().Get(ctx, a.Name, options.GetOptions{})
			if err != nil {
				continue // already gone
			}
			_, err = be.calicoClient.BlockAffinities().Delete(ctx, existing.Name, options.DeleteOptions{ResourceVersion: existing.ResourceVersion})
			if err != nil {
				t.Logf("Warning: failed to delete BlockAffinity %s: %v", a.Name, err)
			}
		}
	}
}

// oneshotTestCase defines a single oneshot confd template rendering test.
// Each test applies input YAML from <goldenDir>/input.yaml, runs confd
// once, and compares the rendered output against golden files in goldenDir.
type oneshotTestCase struct {
	name      string
	goldenDir string

	envVars map[string]string
	kddOnly bool // true if this test requires K8s resources (Services, etc.)
}

// runOneshotTests runs a set of oneshot template tests against all active backends.
func runOneshotTests(t *testing.T, cases []oneshotTestCase) {
	t.Helper()
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range cases {
				if tc.kddOnly && be.ctrlClient == nil {
					continue
				}
				t.Run(tc.name, func(t *testing.T) {
					for k, v := range tc.envVars {
						t.Setenv(k, v)
					}
					runConfdTest(t, be, tc.goldenDir+"/input.yaml", tc.goldenDir)
				})
			}
		})
	}
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

	affinityCleanup := createBlockAffinities(t, be)
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

	// Wait for all resources to be visible through the Calico client. Under
	// CI load the envtest API server can return stale list results briefly
	// after a Create returns, causing the syncer to miss resources.
	waitForResources(t, confdCalicoClient, inputPath)

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
		actualPath := filepath.Join(outputDir, f)
		got, err := os.ReadFile(actualPath)
		require.NoError(t, err, "reading output %s", f)

		expectedPath := filepath.Join("compiled_templates", goldenDir, f)
		want, err := os.ReadFile(expectedPath)
		gotNorm := normalizeBlankLines(string(got))
		if err != nil {
			if updateGoldenFiles && os.IsNotExist(err) {
				t.Logf("creating golden file %s", expectedPath)
				if err := os.MkdirAll(filepath.Dir(expectedPath), 0755); err != nil {
					t.Fatalf("failed to create golden dir for %s: %v", expectedPath, err)
				}
				if err := os.WriteFile(expectedPath, []byte(gotNorm), 0644); err != nil {
					t.Fatalf("failed to create golden file %s: %v", expectedPath, err)
				}
				continue
			}
			require.NoError(t, err, "reading golden file %s", expectedPath)
		}

		wantNorm := normalizeBlankLines(string(want))
		if gotNorm != wantNorm {
			if updateGoldenFiles {
				t.Logf("updating golden file %s", expectedPath)
				if err := os.WriteFile(expectedPath, []byte(gotNorm), 0644); err != nil {
					t.Fatalf("failed to update golden file %s: %v", expectedPath, err)
				}
				continue
			}
			t.Errorf("output mismatch for %s\n\n%s", f, fileDiff(t, expectedPath, actualPath, wantNorm, gotNorm))
		}
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

// fileDiff writes the two normalized strings to temp files and shells out to
// diff -u for a proper unified diff. Falls back to a simple before/after dump
// if diff is unavailable.
func fileDiff(t *testing.T, expectedPath, actualPath, want, got string) string {
	t.Helper()
	wantFile := filepath.Join(t.TempDir(), "expected")
	gotFile := filepath.Join(t.TempDir(), "actual")
	require.NoError(t, os.WriteFile(wantFile, []byte(want), 0644))
	require.NoError(t, os.WriteFile(gotFile, []byte(got), 0644))

	cmd := exec.Command("diff", "-u", "--label", expectedPath, "--label", actualPath, wantFile, gotFile)
	out, err := cmd.Output()
	if err != nil {
		// diff exits 1 when files differ — that's expected.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return string(out)
		}
		return fmt.Sprintf("diff failed: %v\n\n--- expected (%s) ---\n%s\n\n--- actual (%s) ---\n%s", err, expectedPath, want, actualPath, got)
	}
	return string(out)
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

// confdDaemon represents a running confd instance for daemon-mode tests.
// It allows tests to apply resource changes while confd is running and
// poll for output to match expected golden files.
type confdDaemon struct {
	t         *testing.T
	be        *datastoreBackend
	outputDir string
	cancel    context.CancelFunc
	errCh     chan error
}

// confdDaemonOption configures startConfdDaemon.
type confdDaemonOption func(*confdDaemonConfig)

type confdDaemonConfig struct {
	nodeName       string
	skipAffinities bool

	// endpointStatusFiles maps filename → JSON content to write under
	// <tmpDir>/endpoint-status/ before starting confd.
	endpointStatusFiles map[string]string
}

// withNodeName overrides the default "kube-master" node name for this
// confd instance. Sets NODENAME env, template.NodeName, and calico.NodeName.
func withNodeName(name string) confdDaemonOption {
	return func(c *confdDaemonConfig) { c.nodeName = name }
}

// withoutBlockAffinities skips creating the standard block affinities.
func withoutBlockAffinities() confdDaemonOption {
	return func(c *confdDaemonConfig) { c.skipAffinities = true }
}

// withEndpointStatus writes endpoint-status files and sets the env var so
// confd reads them. Used for localWorkloadSelector tests.
func withEndpointStatus(files map[string]string) confdDaemonOption {
	return func(c *confdDaemonConfig) { c.endpointStatusFiles = files }
}

// startConfdDaemon starts confd in daemon mode (not oneshot). The caller
// applies resources and calls expectOutput at each step. Call stop() when done.
func startConfdDaemon(t *testing.T, be *datastoreBackend, opts ...confdDaemonOption) *confdDaemon {
	t.Helper()

	cfg := confdDaemonConfig{nodeName: "kube-master"}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.nodeName != "kube-master" {
		t.Setenv("NODENAME", cfg.nodeName)
		template.NodeName = cfg.nodeName
		calico.NodeName = cfg.nodeName
		t.Cleanup(func() {
			template.NodeName = "kube-master"
			calico.NodeName = "kube-master"
		})
	}

	tmpDir := t.TempDir()
	confDir := filepath.Join(tmpDir, "confd")
	outputDir := filepath.Join(confDir, "config")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	srcConfDir := filepath.Join("..", "etc", "calico", "confd")
	copyDir(t, filepath.Join(srcConfDir, "conf.d"), filepath.Join(confDir, "conf.d"))
	copyDir(t, filepath.Join(srcConfDir, "templates"), filepath.Join(confDir, "templates"))
	rewriteDestPaths(t, filepath.Join(confDir, "conf.d"), outputDir)

	if len(cfg.endpointStatusFiles) > 0 {
		esDir := filepath.Join(tmpDir, "endpoint-status")
		require.NoError(t, os.MkdirAll(esDir, 0755))
		for name, content := range cfg.endpointStatusFiles {
			require.NoError(t, os.WriteFile(filepath.Join(esDir, name), []byte(content), 0644))
		}
		t.Setenv("CALICO_ENDPOINT_STATUS_PATH_PREFIX", tmpDir)
	}

	if !cfg.skipAffinities {
		t.Cleanup(createBlockAffinities(t, be))
	}

	confdCalicoClient, err := client.New(apiconfig.CalicoAPIConfig{Spec: be.datastoreConfig})
	require.NoError(t, err, "creating confd Calico client")

	confdConfig := &config.Config{
		ConfDir:  confDir,
		Onetime:  false,
		SyncOnly: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run.RunWithContext(
			ctx,
			confdConfig,
			confdCalicoClient,
			be.k8sClientset,
			be.datastoreConfig,
			&syncclientutils.TyphaConfig{},
			nil,
		)
	}()

	// Wait briefly for confd to start and sync.
	time.Sleep(500 * time.Millisecond)

	d := &confdDaemon{
		t:         t,
		be:        be,
		outputDir: outputDir,
		cancel:    cancel,
		errCh:     errCh,
	}
	t.Cleanup(d.stop)
	return d
}

// stop shuts down the running confd instance.
func (d *confdDaemon) stop() {
	d.cancel()
	select {
	case err := <-d.errCh:
		if err != nil {
			d.t.Logf("confd daemon exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		d.t.Log("confd daemon did not stop within 5s")
	}
}

// expectOutput polls until the rendered output matches the golden files in
// goldenDir, with a timeout of 10 seconds (matching the bash test behavior).
func (d *confdDaemon) expectOutput(goldenDir string) {
	d.t.Helper()

	goldenFiles := []string{
		"bird.cfg",
		"bird6.cfg",
		"bird_ipam.cfg",
		"bird6_ipam.cfg",
		"bird_aggr.cfg",
		"bird6_aggr.cfg",
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		allMatch := true
		var lastMismatch string
		for _, f := range goldenFiles {
			actualPath := filepath.Join(d.outputDir, f)
			got, err := os.ReadFile(actualPath)
			if err != nil {
				allMatch = false
				lastMismatch = fmt.Sprintf("%s: %v", f, err)
				break
			}

			expectedPath := filepath.Join("compiled_templates", goldenDir, f)
			want, err := os.ReadFile(expectedPath)
			if err != nil {
				if updateGoldenFiles && os.IsNotExist(err) {
					allMatch = false
					lastMismatch = fmt.Sprintf("%s missing, will create", expectedPath)
					break
				}
				d.t.Fatalf("reading golden file %s: %v", expectedPath, err)
			}

			if normalizeBlankLines(string(got)) != normalizeBlankLines(string(want)) {
				allMatch = false
				lastMismatch = fmt.Sprintf("%s does not match %s:\n%v", f, expectedPath, normalizeBlankLines(string(got)))
				break
			}
		}

		if allMatch {
			return
		}

		if time.Now().After(deadline) {
			if updateGoldenFiles {
				d.updateGoldenFiles(goldenDir, goldenFiles)
				return
			}
			d.t.Fatalf("timed out waiting for output to match %s (last mismatch: %s)", goldenDir, lastMismatch)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// updateGoldenFiles overwrites the golden files with the current rendered output.
func (d *confdDaemon) updateGoldenFiles(goldenDir string, files []string) {
	d.t.Helper()
	for _, f := range files {
		actualPath := filepath.Join(d.outputDir, f)
		got, err := os.ReadFile(actualPath)
		if err != nil {
			d.t.Logf("skipping %s: %v", f, err)
			continue
		}
		expectedPath := filepath.Join("compiled_templates", goldenDir, f)
		d.t.Logf("updating golden file %s", expectedPath)
		if err := os.MkdirAll(filepath.Dir(expectedPath), 0755); err != nil {
			d.t.Fatalf("failed to create golden dir for %s: %v", expectedPath, err)
		}
		if err := os.WriteFile(expectedPath, []byte(normalizeBlankLines(string(got))), 0644); err != nil {
			d.t.Fatalf("failed to update golden file %s: %v", expectedPath, err)
		}
	}
}

// expectPeeringCount polls until bird.cfg contains exactly n "protocol bgp"
// stanzas, with a timeout of 10 seconds.
func (d *confdDaemon) expectPeeringCount(n int) {
	d.t.Helper()

	birdCfg := filepath.Join(d.outputDir, "bird.cfg")
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(birdCfg)
		if err == nil {
			count := strings.Count(string(data), "protocol bgp")
			if count == n {
				return
			}
			if time.Now().After(deadline) {
				d.t.Fatalf("expected %d peerings, got %d in %s\n\n%s", n, count, birdCfg, string(data))
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}
