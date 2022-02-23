// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/onsi/ginkgo"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

type K8sDatastoreInfra struct {
	etcdContainer        *containers.Container
	bpfLog               *containers.Container
	k8sApiContainer      *containers.Container
	k8sControllerManager *containers.Container

	calicoClient client.Interface
	K8sClient    *kubernetes.Clientset

	Endpoint    string
	EndpointIP  string
	BadEndpoint string

	CertFileName string

	// needsCleanup is set when we're told to Stop() in order to trigger deferred cleanup
	// before the next test.  (If there is no next test, we'll skip the cleanup.)
	needsCleanup bool

	runningTest string
}

var (
	// This transport is based on  http.DefaultTransport, with InsecureSkipVerify set.
	insecureTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ExpectContinueTimeout: 1 * time.Second,
	}
	insecureHTTPClient = http.Client{
		Transport: insecureTransport,
	}

	K8sInfra *K8sDatastoreInfra
)

func TearDownK8sInfra(kds *K8sDatastoreInfra) {
	log.Info("TearDownK8sInfra starting")
	var wg sync.WaitGroup

	if kds.etcdContainer != nil {
		kds.etcdContainer.StopLogs()
	}
	if kds.k8sApiContainer != nil {
		kds.k8sApiContainer.StopLogs()
	}
	if kds.k8sControllerManager != nil {
		kds.k8sControllerManager.StopLogs()
	}

	if kds.etcdContainer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kds.etcdContainer.Stop()
		}()
	}
	if kds.k8sApiContainer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kds.k8sApiContainer.Stop()
		}()
	}
	if kds.k8sControllerManager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kds.k8sControllerManager.Stop()
		}()
	}
	wg.Wait()
	log.Info("TearDownK8sInfra done")
}

func createK8sDatastoreInfra() DatastoreInfra {
	infra, err := GetK8sDatastoreInfra()
	Expect(err).NotTo(HaveOccurred())
	return infra
}

func GetK8sDatastoreInfra() (*K8sDatastoreInfra, error) {
	if K8sInfra != nil {
		if K8sInfra.runningTest != "" {
			ginkgo.Fail(fmt.Sprintf("Previous test didn't clean up the infra: %s", K8sInfra.runningTest))
		}
		K8sInfra.EnsureReady()
		K8sInfra.PerTestSetup()
		return K8sInfra, nil
	}

	var err error
	K8sInfra, err = setupK8sDatastoreInfra()
	if err == nil {
		K8sInfra.PerTestSetup()
	}

	return K8sInfra, err
}

func (kds *K8sDatastoreInfra) PerTestSetup() {
	// In BPF mode, start BPF logging.
	if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
		kds.bpfLog = containers.Run("bpf-log", containers.RunOpts{AutoRemove: true}, "--privileged",
			"calico/bpftool:v5.3-amd64", "/bpftool", "prog", "tracelog")
	}
	K8sInfra.runningTest = ginkgo.CurrentGinkgoTestDescription().FullTestText
}

func runK8sApiserver(etcdIp string) *containers.Container {
	return containers.Run("apiserver",
		containers.RunOpts{
			AutoRemove: true,
			StopSignal: "SIGKILL",
		},
		"-v", os.Getenv("CERTS_PATH")+":/home/user/certs", // Mount in location of certificates.
		utils.Config.K8sImage,
		"kube-apiserver",
		"--v=0",
		"--service-cluster-ip-range=10.101.0.0/16",
		"--authorization-mode=RBAC",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdIp),
		"--service-account-key-file=/home/user/certs/service-account.pem",
		"--service-account-signing-key-file=/home/user/certs/service-account-key.pem",
		"--service-account-issuer=https://localhost:443",
		"--api-audiences=kubernetes.default",
		"--client-ca-file=/home/user/certs/ca.pem",
		"--tls-cert-file=/home/user/certs/kubernetes.pem",
		"--tls-private-key-file=/home/user/certs/kubernetes-key.pem",
		"--enable-priority-and-fairness=false",
		"--max-mutating-requests-inflight=0",
		"--max-requests-inflight=0",
	)
}

func runK8sControllerManager(apiserverIp string) *containers.Container {
	c := containers.Run("controller-manager",
		containers.RunOpts{
			AutoRemove: true,
			StopSignal: "SIGKILL",
		},
		"-v", os.Getenv("CERTS_PATH")+"/:/home/user/certs", // Mount in location of certificates.
		utils.Config.K8sImage,
		"kube-controller-manager",
		fmt.Sprintf("--master=https://%v:6443", apiserverIp),
		"--kubeconfig=/home/user/certs/kube-controller-manager.kubeconfig",
		// We run trivially small clusters, so increase the QPS to get the
		// cluster to start up as fast as possible.
		"--kube-api-qps=100",
		"--kube-api-burst=200",
		"--min-resync-period=3m",
		// Disable node CIDRs since the controller manager stalls for 10s if
		// they are enabled.
		"--allocate-node-cidrs=false",
		"--leader-elect=false",
		"--v=0",
		"--service-account-private-key-file=/home/user/certs/service-account-key.pem",
		"--root-ca-file=/home/user/certs/ca.pem",
		"--concurrent-gc-syncs=50",
	)
	return c
}

func setupK8sDatastoreInfra() (*K8sDatastoreInfra, error) {
	log.Info("Starting Kubernetes infrastructure")

	log.Info("Starting etcd")
	kds := &K8sDatastoreInfra{}

	// Start etcd, which will back the k8s API server.
	kds.etcdContainer = RunEtcd()
	if kds.etcdContainer == nil {
		return nil, errors.New("failed to create etcd container")
	}
	log.Info("Started etcd")

	// Start the k8s API server.
	//
	// The clients in this test - Felix, Typha and the test code itself - all connect
	// anonymously to the API server, because (a) they aren't running in pods in a proper
	// Kubernetes cluster, and (b) they don't provide client TLS certificates, and (c) they
	// don't use any of the other non-anonymous mechanisms that Kubernetes supports.  But, as of
	// 1.6, the API server doesn't allow anonymous users with the default "AlwaysAllow"
	// authorization mode.  So we specify the "RBAC" authorization mode instead, and create a
	// ClusterRoleBinding that gives the "system:anonymous" user unlimited power (aka the
	// "cluster-admin" role).
	log.Info("Starting API server")
	kds.k8sApiContainer = runK8sApiserver(kds.etcdContainer.IP)

	if kds.k8sApiContainer == nil {
		TearDownK8sInfra(kds)
		return nil, errors.New("failed to create k8s API server container")
	}

	log.Info("Started API server")

	start := time.Now()
	for {
		var err error
		kds.K8sClient, err = kubernetes.NewForConfig(&rest.Config{
			Transport: insecureTransport,
			Host:      "https://" + kds.k8sApiContainer.IP + ":6443",
			QPS:       100,
			Burst:     100,
		})
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second {
			log.WithError(err).Error("Failed to create k8s client.")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Info("Got k8s client")

	// Allow anonymous connections to the API server.  We also use this command to wait
	// for the API server to be up.
	start = time.Now()
	for {
		err := kds.k8sApiContainer.ExecMayFail(
			"kubectl", "create", "clusterrolebinding",
			"anonymous-admin",
			"--insecure-skip-tls-verify=true",
			"--client-key=/home/user/certs/admin-key.pem",
			"--client-certificate=/home/user/certs/admin.pem",
			fmt.Sprintf("--server=https://%s:6443", kds.k8sApiContainer.IP),
			"--clusterrole=cluster-admin",
			"--user=system:anonymous",
		)
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "already exists") {
			// Sometimes hit an "already exists" error here; I suspect the account we create is
			// also added by the controller manager.  It doesn't matter who wins.
			break
		}
		if time.Since(start) > 90*time.Second {
			log.WithError(err).Error("Failed to install role binding")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Info("Added role binding.")

	start = time.Now()
	for {
		_, err := kds.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		if err == nil {
			break
		}
		if time.Since(start) > 15*time.Second {
			log.WithError(err).Error("Failed to list namespaces.")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Info("List namespaces successfully.")

	log.Info("Starting controller manager.")
	kds.k8sControllerManager = runK8sControllerManager(kds.k8sApiContainer.IP)
	if kds.k8sApiContainer == nil {
		TearDownK8sInfra(kds)
		return nil, errors.New("failed to create k8s contoller manager container")
	}

	log.Info("Started controller manager.")

	// Copy CRD registration manifests into the API server container, and apply it.
	err := kds.k8sApiContainer.CopyFileIntoContainer("../../libcalico-go/config/crd", "/crds")
	if err != nil {
		TearDownK8sInfra(kds)
		return nil, err
	}

	err = kds.k8sApiContainer.ExecMayFail("kubectl", "--kubeconfig=/home/user/certs/kubeconfig", "apply", "-f", "/crds/")
	if err != nil {
		TearDownK8sInfra(kds)
		return nil, err
	}

	kds.EndpointIP = kds.k8sApiContainer.IP
	kds.Endpoint = fmt.Sprintf("https://%s:6443", kds.k8sApiContainer.IP)
	kds.BadEndpoint = fmt.Sprintf("https://%s:1234", kds.k8sApiContainer.IP)

	start = time.Now()
	for {
		var resp *http.Response
		resp, err = insecureHTTPClient.Get(kds.Endpoint + "/apis/crd.projectcalico.org/v1/felixconfigurations")
		if resp.StatusCode != 200 {
			err = fmt.Errorf("Bad status (%v) for CRD GET request", resp.StatusCode)
		}
		if err != nil || resp.StatusCode != 200 {
			log.WithError(err).WithField("status", resp.StatusCode).Warn("Waiting for API server to respond to requests")
		}
		resp.Body.Close()
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second {
			log.WithError(err).Error("API server is not responding to requests")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Info("API server is up.")

	kds.CertFileName = "/tmp/" + kds.k8sApiContainer.Name + ".crt"
	start = time.Now()
	for {
		cmd := utils.Command("docker", "cp",
			kds.k8sApiContainer.Name+":/home/user/certs/kubernetes.pem",
			kds.CertFileName,
		)
		err = cmd.Run()
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second {
			log.WithError(err).Error("Failed to get API server cert")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	start = time.Now()
	for {
		kds.calicoClient, err = client.New(apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           kds.Endpoint,
					K8sInsecureSkipTLSVerify: true,
					K8sClientQPS:             100,
				},
			},
		})
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = kds.calicoClient.EnsureInitialized(
				ctx,
				"v3.0.0-test",
				"felix-fv,typha", // Including typha in clusterType to prevent config churn
			)
			cancel()
			if err == nil {
				break
			}
		}
		if time.Since(start) > 120*time.Second && err != nil {
			log.WithError(err).Error("Failed to initialise calico client")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Info("Wait for creating default service account")
	start = time.Now()
	for {
		_, err := kds.K8sClient.CoreV1().ServiceAccounts("default").Get(context.Background(), "default", metav1.GetOptions{})
		if err == nil {
			break
		}
		if time.Since(start) > 20*time.Second {
			log.WithError(err).Error("Failed to get default service account.")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Info("Controller manager is up. k8s datastore setup is done")
	return kds, nil
}

func (kds *K8sDatastoreInfra) EnsureReady() {
	if kds.needsCleanup {
		log.Info("Infra marked for clean up, cleaning up before test.")
		kds.CleanUp()
	}
	info, err := kds.GetCalicoClient().ClusterInformation().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	if err != nil {
		panic(err)
	}
	ready := true
	info.Spec.DatastoreReady = &ready
	_, err = kds.GetCalicoClient().ClusterInformation().Update(
		context.Background(),
		info,
		options.SetOptions{},
	)
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) Stop() {
	// We don't tear down and recreate the Kubernetes infra between tests because it's
	// too expensive.  We don't even, immediately, clean up any resources that may
	// have been left behind by the test that has just finished.  Instead, mark all
	// our resources for cleanup, but defer the cleanup until the start of the next
	// test (this allows us to skip the cleanup if we happen to be the last test to
	// run, which is a big win when manually running a single test for debugging.)
	log.Info("K8sDatastoreInfra told to stop, deferring cleanup...")
	kds.needsCleanup = true
	kds.runningTest = ""

	kds.bpfLog.Stop()
}

type cleanupFunc func(clientset *kubernetes.Clientset, calicoClient client.Interface)

func (kds *K8sDatastoreInfra) CleanUp() {
	log.Info("Cleaning up kubernetes datastore")
	startTime := time.Now()
	for _, f := range []cleanupFunc{
		cleanupAllPods,
		cleanupAllNodes,
		cleanupAllNamespaces,
		cleanupAllPools,
		cleanupIPAM,
		cleanupAllGlobalNetworkPolicies,
		cleanupAllNetworkPolicies,
		cleanupAllHostEndpoints,
		cleanupAllFelixConfigurations,
		cleanupAllServices,
	} {
		f(kds.K8sClient, kds.calicoClient)
	}
	kds.needsCleanup = false
	log.WithField("time", time.Since(startTime)).Info("Cleaned up kubernetes datastore")
}

func cleanupIPAM(clientset *kubernetes.Clientset, calicoClient client.Interface) {
	log.Info("Cleaning up IPAM")
	c := calicoClient.(interface{ Backend() bapi.Client }).Backend()
	for _, li := range []model.ListInterface{
		model.BlockListOptions{},
		model.BlockAffinityListOptions{},
		model.BlockAffinityListOptions{},
		model.IPAMHandleListOptions{},
	} {
		if rs, err := c.List(context.Background(), li, ""); err != nil {
			log.WithError(err).WithField("Kind", li).Warning("Failed to list resources")
		} else {
			for _, r := range rs.KVPairs {
				if _, err = c.DeleteKVP(context.Background(), r); err != nil {
					log.WithError(err).WithField("Key", r.Key).Warning("Failed to delete entry from KDD")
				}
			}
		}
	}
}

func (kds *K8sDatastoreInfra) GetDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=kubernetes",
		"-e", "FELIX_DATASTORETYPE=kubernetes",
		"-e", "TYPHA_DATASTORETYPE=kubernetes",
		"-e", "K8S_API_ENDPOINT=" + kds.Endpoint,
		"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
		"-v", kds.CertFileName + ":/tmp/apiserver.crt",
	}
}

func (kds *K8sDatastoreInfra) GetBadEndpointDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=kubernetes",
		"-e", "FELIX_DATASTORETYPE=kubernetes",
		"-e", "TYPHA_DATASTORETYPE=kubernetes",
		"-e", "K8S_API_ENDPOINT=" + kds.BadEndpoint,
		"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
		"-v", kds.CertFileName + ":/tmp/apiserver.crt",
	}
}

func (kds *K8sDatastoreInfra) GetCalicoClient() client.Interface {
	return kds.calicoClient
}

func (kds *K8sDatastoreInfra) GetClusterGUID() string {
	ci, err := kds.GetCalicoClient().ClusterInformation().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	return ci.Spec.ClusterGUID
}

func (kds *K8sDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, idx int, needBGP bool) {
	felix.ExpectedIPIPTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedIPIPTunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExpectedVXLANTunnelAddr(felix *Felix, idx int, needBGP bool) {
	felix.ExpectedVXLANTunnelAddr = fmt.Sprintf("10.65.%d.0", idx)
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedVXLANTunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExpectedWireguardTunnelAddr(felix *Felix, idx int, needWg bool) {
	// Set to be the same as IPIP tunnel address.
	felix.ExpectedWireguardTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedWireguardTunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExternalIP(felix *Felix, idx int) {
	felix.ExternalIP = fmt.Sprintf("111.222.%d.1", idx)
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExternalIP)
}

func (kds *K8sDatastoreInfra) RemoveNodeAddresses(felix *Felix) {
	node, err := kds.K8sClient.CoreV1().Nodes().Get(context.Background(), felix.Hostname, metav1.GetOptions{})
	if err != nil {
		panic(err)
	}
	node.Status.Addresses = []v1.NodeAddress{}
	_, err = kds.K8sClient.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) AddNode(felix *Felix, idx int, needBGP bool) {
	nodeIn := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: felix.Hostname,
			Annotations: map[string]string{
				"projectcalico.org/IPv4Address": fmt.Sprintf("%s/%s", felix.IP, felix.IPPrefix),
			},
		},
		Spec: v1.NodeSpec{PodCIDR: fmt.Sprintf("10.65.%d.0/24", idx)},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{
				Address: felix.IP,
				Type:    v1.NodeInternalIP,
			}},
		},
	}
	if felix.ExternalIP != "" {
		nodeIn.Status.Addresses = append(nodeIn.Status.Addresses,
			v1.NodeAddress{
				Address: felix.ExternalIP,
				Type:    v1.NodeInternalIP,
			})
	}
	if felix.ExpectedIPIPTunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv4IPIPTunnelAddr"] = felix.ExpectedIPIPTunnelAddr
	}
	if felix.ExpectedVXLANTunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv4VXLANTunnelAddr"] = felix.ExpectedVXLANTunnelAddr
	}
	if felix.ExpectedWireguardTunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv4WireguardInterfaceAddr"] = felix.ExpectedWireguardTunnelAddr
	}
	log.WithField("nodeIn", nodeIn).Debug("Node defined")
	nodeOut, err := kds.K8sClient.CoreV1().Nodes().Create(context.Background(), nodeIn, metav1.CreateOptions{})
	log.WithField("nodeOut", nodeOut).Debug("Created node")
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) ensureNamespace(name string) {
	// Try to get namespace. Return if it already exists.
	_, err := kds.K8sClient.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	if err == nil {
		return
	}

	if !apierrs.IsNotFound(err) {
		panic(err)
	}

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err = kds.K8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) RemoveWorkload(ns, name string) error {
	wepIDs, err := names.ParseWorkloadEndpointName(name)
	if err != nil {
		return err
	}
	err = kds.K8sClient.CoreV1().Pods(ns).Delete(context.Background(), wepIDs.Pod, DeleteImmediately)
	return err
}

func (kds *K8sDatastoreInfra) AddWorkload(wep *libapi.WorkloadEndpoint) (*libapi.WorkloadEndpoint, error) {
	podIP := wep.Spec.IPNetworks[0]
	if strings.Contains(podIP, "/") {
		// Our WEP will have a /32 rather than an IP, strip it off.
		podIP = strings.Split(podIP, "/")[0]
	}
	desiredStatus := v1.PodStatus{
		Phase: v1.PodRunning,
		Conditions: []v1.PodCondition{
			{
				Type:   v1.PodScheduled,
				Status: v1.ConditionTrue,
			},
			{
				Type:   v1.PodReady,
				Status: v1.ConditionTrue,
			},
		},
		PodIP: podIP,
	}
	podIn := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: wep.Spec.Workload, Namespace: wep.Namespace},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name:  wep.Spec.Endpoint,
				Image: "ignore",
			}},
			NodeName: wep.Spec.Node,
		},
		Status: desiredStatus,
	}
	if wep.Labels != nil {
		podIn.ObjectMeta.Labels = wep.Labels
	}
	log.WithField("podIn", podIn).Debug("Creating Pod for workload")
	kds.ensureNamespace(wep.Namespace)
	podOut, err := kds.K8sClient.CoreV1().Pods(wep.Namespace).Create(context.Background(), podIn, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("podOut", podOut).Debug("Created pod")
	podIn = podOut
	podIn.Status = desiredStatus
	podOut, err = kds.K8sClient.CoreV1().Pods(wep.Namespace).UpdateStatus(context.Background(), podIn, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("podOut", podOut).Debug("Updated pod status")

	wepid := names.WorkloadEndpointIdentifiers{
		Node:         wep.Spec.Node,
		Orchestrator: "k8s",
		Endpoint:     "eth0",
		Pod:          wep.Spec.Workload,
	}

	name, err := wepid.CalculateWorkloadEndpointName(false)
	if err != nil {
		panic(err)
	}
	log.WithField("name", name).Debug("Getting WorkloadEndpoint")
	return kds.calicoClient.WorkloadEndpoints().Get(context.Background(), wep.Namespace, name, options.GetOptions{})
}

func (kds *K8sDatastoreInfra) AddAllowToDatastore(selector string) error {
	// Create a policy to allow egress from the host so that we don't cut off Felix's datastore connection
	// when we enable the host endpoint.
	policy := api.NewGlobalNetworkPolicy()
	policy.Name = "allow-egress"
	policy.Spec.Selector = selector
	policy.Spec.Egress = []api.Rule{{
		Action: api.Allow,
		Destination: api.EntityRule{
			Nets: []string{kds.k8sApiContainer.IP + "/32"},
		},
	}}
	_, err := kds.calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	return err
}

func (kds *K8sDatastoreInfra) AddDefaultAllow() string {
	return "kns.default"
}

func (kds *K8sDatastoreInfra) AddDefaultDeny() error {
	policy := api.NewNetworkPolicy()
	policy.Name = "deny-all"
	policy.Namespace = "default"
	policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
	policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
	policy.Spec.Selector = "all()"
	_, err := kds.calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	return err
}

func (kds *K8sDatastoreInfra) DumpErrorData() {
	nsList, err := kds.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Kubernetes Namespaces:")
		for _, ns := range nsList.Items {
			log.Info(spew.Sdump(ns))
		}
	}

	profiles, err := kds.calicoClient.Profiles().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico Profiles:")
		for _, profile := range profiles.Items {
			log.Info(spew.Sdump(profile))
		}
	}
	policies, err := kds.calicoClient.NetworkPolicies().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico NetworkPolicies:")
		for _, policy := range policies.Items {
			log.Info(spew.Sdump(policy))
		}
	}
	gnps, err := kds.calicoClient.GlobalNetworkPolicies().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico GlobalNetworkPolicies:")
		for _, gnp := range gnps.Items {
			log.Info(spew.Sdump(gnp))
		}
	}
	workloads, err := kds.calicoClient.WorkloadEndpoints().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico WorkloadEndpoints:")
		for _, w := range workloads.Items {
			log.Info(spew.Sdump(w))
		}
	}
	nodes, err := kds.calicoClient.Nodes().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico Nodes:")
		for _, n := range nodes.Items {
			log.Info(spew.Sdump(n))
		}
	}
	heps, err := kds.calicoClient.HostEndpoints().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico Host Endpoints:")
		for _, hep := range heps.Items {
			log.Info(spew.Sdump(hep))
		}
	}
}

var (
	zeroGracePeriod   int64 = 0
	DeleteImmediately       = metav1.DeleteOptions{
		GracePeriodSeconds: &zeroGracePeriod,
	}
)

func isSystemNamespace(ns string) bool {
	return ns == "default" || ns == "kube-system" || ns == "kube-public"
}

func cleanupAllNamespaces(clientset *kubernetes.Clientset, calicoClient client.Interface) {
	log.Info("Cleaning up all namespaces...")
	nsList, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nsList.Items)).Info("Namespaces present")
	for _, ns := range nsList.Items {
		if ns.Status.Phase != v1.NamespaceTerminating && !isSystemNamespace(ns.ObjectMeta.Name) {
			err = clientset.CoreV1().Namespaces().Delete(context.Background(), ns.ObjectMeta.Name, DeleteImmediately)
			if err != nil {
				panic(err)
			}
		}
	}
	log.Info("Cleaned up all namespaces")
}

func cleanupAllNodes(clientset *kubernetes.Clientset, calicoClient client.Interface) {
	log.Info("Cleaning up all nodes...")
	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nodeList.Items)).Info("Nodes present")
	for _, node := range nodeList.Items {
		err = clientset.CoreV1().Nodes().Delete(context.Background(), node.ObjectMeta.Name, DeleteImmediately)
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up all nodes")
}

func cleanupAllPods(clientset *kubernetes.Clientset, calicoClient client.Interface) {
	log.Info("Cleaning up Pods")
	nsList, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nsList.Items)).Info("Namespaces present")
	podsDeleted := 0
	admission := make(chan int, 10)
	waiter := sync.WaitGroup{}
	waiter.Add(len(nsList.Items))
	for _, ns := range nsList.Items {
		nsName := ns.ObjectMeta.Name
		go func() {
			admission <- 1
			podList, err := clientset.CoreV1().Pods(nsName).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				panic(err)
			}
			log.WithField("count", len(podList.Items)).WithField("namespace", nsName).Debug(
				"Pods present")
			for _, pod := range podList.Items {
				err = clientset.CoreV1().Pods(nsName).Delete(context.Background(), pod.ObjectMeta.Name, DeleteImmediately)
				if err != nil {
					panic(err)
				}
			}
			podsDeleted += len(podList.Items)
			<-admission
			waiter.Done()
		}()
	}
	waiter.Wait()

	log.WithField("podsDeleted", podsDeleted).Info("Cleaned up all pods")
}

func cleanupAllPools(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up IPAM pools")
	ctx := context.Background()
	pools, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(pools.Items)).Info("IP Pools present")
	for _, pool := range pools.Items {
		_, err = client.IPPools().Delete(ctx, pool.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up IPAM")
}

func cleanupAllGlobalNetworkPolicies(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up GNPs")
	ctx := context.Background()
	gnps, err := client.GlobalNetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(gnps.Items)).Info("Global Network Policies present")
	for _, gnp := range gnps.Items {
		_, err = client.GlobalNetworkPolicies().Delete(ctx, gnp.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up GNPs")
}

func cleanupAllNetworkPolicies(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up network policies")
	ctx := context.Background()
	nps, err := client.NetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nps.Items)).Info("Global Network Policies present")
	for _, np := range nps.Items {
		_, err = client.NetworkPolicies().Delete(ctx, np.Namespace, np.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up network policies")
}

func cleanupAllHostEndpoints(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up host endpoints")
	ctx := context.Background()
	heps, err := client.HostEndpoints().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(heps.Items)).Info("HostEndpoints present")
	for _, hep := range heps.Items {
		_, err = client.HostEndpoints().Delete(ctx, hep.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up host endpoints")
}

func cleanupAllFelixConfigurations(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up felix configurations")
	ctx := context.Background()
	fcs, err := client.FelixConfigurations().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(fcs.Items)).Info("FelixConfigurations present")
	for _, fc := range fcs.Items {
		_, err = client.FelixConfigurations().Delete(ctx, fc.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up felix configurations")
}

func cleanupAllServices(clientset *kubernetes.Clientset, calicoClient client.Interface) {
	log.Info("Cleaning up services")
	coreV1 := clientset.CoreV1()
	namespaceList, err := coreV1.Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, ns := range namespaceList.Items {
		serviceInterface := coreV1.Services(ns.Name)
		services, err := serviceInterface.List(context.Background(), metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, s := range services.Items {
			if s.Name == "kubernetes" {
				// Skip cleaning up the Kubernetes API service.
				continue
			}
			err := serviceInterface.Delete(context.Background(), s.Name, metav1.DeleteOptions{})
			if err != nil {
				panic(err)
			}
		}
		endpointsInterface := coreV1.Endpoints(ns.Name)
		endpoints, err := endpointsInterface.List(context.Background(), metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, ep := range endpoints.Items {
			if ep.Name == "kubernetes" {
				// Skip cleaning up the Kubernetes API service.
				continue
			}
			err := endpointsInterface.Delete(context.Background(), ep.Name, metav1.DeleteOptions{})
			if err != nil && !strings.Contains(err.Error(), "not found") {
				panic(err)
			}
		}
	}
	log.Info("Cleaned up services")
}
