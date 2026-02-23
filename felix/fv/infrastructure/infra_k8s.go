// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const DefaultBPFLogByteLimit = 64 * 1024 * 1024

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

	ipv6                  bool
	dualStack             bool
	serviceClusterIPRange string
	apiServerBindIP       string
	ipMask                string

	cleanups        cleanupStack
	felixes         []*Felix
	bpfLogByteLimit int
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

	// Currently only require a single instance.
	K8sInfra [1]*K8sDatastoreInfra
)

type K8sInfraIndex int

const (
	K8SInfraLocalCluster K8sInfraIndex = 0
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
		wg.Go(func() {
			kds.etcdContainer.Stop()
		})
	}
	if kds.k8sApiContainer != nil {
		wg.Go(func() {
			kds.k8sApiContainer.Stop()
		})
	}
	if kds.k8sControllerManager != nil {
		wg.Go(func() {
			kds.k8sControllerManager.Stop()
		})
	}
	wg.Wait()
	log.Info("TearDownK8sInfra done")
}

func createK8sDatastoreInfra(opts ...CreateOption) DatastoreInfra {
	return createK8sDatastoreInfraWithIndex(K8SInfraLocalCluster, opts...)
}

func createK8sDatastoreInfraWithIndex(index K8sInfraIndex, opts ...CreateOption) DatastoreInfra {
	infra, err := GetK8sDatastoreInfra(index, opts...)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return infra
}

func GetK8sDatastoreInfra(index K8sInfraIndex, opts ...CreateOption) (*K8sDatastoreInfra, error) {
	var temp K8sDatastoreInfra

	for _, o := range opts {
		o(&temp)
	}

	kds := K8sInfra[index]

	if kds != nil {
		if kds.runningTest != "" {
			ginkgo.Fail(fmt.Sprintf("Previous test didn't clean up the infra: %s", K8sInfra[index].runningTest))
		}

		resetAll := temp.ipv6 != kds.ipv6 || temp.dualStack != kds.dualStack

		if !resetAll {
			kds.bpfLogByteLimit = temp.bpfLogByteLimit
			kds.EnsureReady()
			kds.PerTestSetup(index)
			return kds, nil
		}

		TearDownK8sInfra(kds)
		K8sInfra[index] = nil
	}

	var err error
	K8sInfra[index], err = setupK8sDatastoreInfra(opts...)
	if err == nil {
		K8sInfra[index].PerTestSetup(index)
	}

	return K8sInfra[index], err
}

func (kds *K8sDatastoreInfra) setBPFLogByteLimit(limit int) {
	kds.bpfLogByteLimit = limit
}

func (kds *K8sDatastoreInfra) PerTestSetup(index K8sInfraIndex) {
	if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" && index == K8SInfraLocalCluster {
		kds.bpfLog = RunBPFLog(kds, kds.bpfLogByteLimit)
	}
	K8sInfra[index].runningTest = ginkgo.CurrentSpecReport().FullText()
}

type CleanupProvider interface {
	AddCleanup(func())
}

func RunBPFLog(cp CleanupProvider, byteLimit int) *containers.Container {
	if byteLimit == 0 {
		byteLimit = DefaultBPFLogByteLimit
	}
	c := containers.Run("bpf-log",
		containers.RunOpts{
			AutoRemove:       true,
			IgnoreEmptyLines: true,
			LogLimitBytes:    byteLimit,
		}, "--privileged",
		utils.Config.FelixImage, "/usr/bin/bpftool", "prog", "tracelog")
	cp.AddCleanup(c.Stop)
	cp.AddCleanup(c.StopLogs)
	return c
}

func (kds *K8sDatastoreInfra) runK8sApiserver() {
	// Get current working dir as docker does not accept relative paths for mounting volumes
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	crdPath := os.Getenv("CALICO_CRD_PATH")

	args := []string{
		"-v", os.Getenv("CERTS_PATH") + ":/home/user/certs", // Mount in location of certificates.
		"-v", fmt.Sprintf("%s/../../%s:/crds", pwd, crdPath), // Mount in location of CRDs.
		utils.Config.K8sImage,
		"kube-apiserver",
		"--v=0",
		// NOTE! We must disable UnauthenticatedHTTP2DOSMitigation in our FV's.
		// Felix uses the anonymous user for API requests in the FVs, which triggers the above feature and leads to very slow networking, and test timeouts.
		"--feature-gates=UnauthenticatedHTTP2DOSMitigation=false",
		"--service-cluster-ip-range=" + kds.serviceClusterIPRange,
		"--authorization-mode=RBAC",
		fmt.Sprintf("--etcd-servers=http://%s:2379", kds.containerGetIPForURL(kds.etcdContainer)),
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
	}

	if kds.apiServerBindIP != "" {
		args = append(args, "--bind-address="+kds.apiServerBindIP)
	}

	apiserver := containers.Run("apiserver",
		containers.RunOpts{
			AutoRemove: true,
			StopSignal: "SIGKILL",
		},
		args...,
	)

	kds.k8sApiContainer = apiserver
}

func (kds *K8sDatastoreInfra) runK8sControllerManager() {
	args := []string{
		"-v", os.Getenv("CERTS_PATH") + "/:/home/user/certs", // Mount in location of certificates.
		utils.Config.K8sImage,
		"kube-controller-manager",
		fmt.Sprintf("--master=https://%v:6443", kds.containerGetIPForURL(kds.k8sApiContainer)),
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
	}

	if kds.serviceClusterIPRange != "" {
		args = append(args, "--service-cluster-ip-range="+kds.serviceClusterIPRange)
	}

	c := containers.Run("controller-manager",
		containers.RunOpts{
			AutoRemove: true,
			StopSignal: "SIGKILL",
		},
		args...,
	)

	kds.k8sControllerManager = c
}

func setupK8sDatastoreInfra(opts ...CreateOption) (kds *K8sDatastoreInfra, err error) {
	log.Info("Starting Kubernetes infrastructure")

	log.Info("Starting etcd")
	kds = &K8sDatastoreInfra{
		serviceClusterIPRange: "10.101.0.0/16",
		ipMask:                "/32",
	}
	defer func() {
		if err != nil {
			log.Warn("setupK8sDatastoreInfra about to fail, tearing down the infra.")
			TearDownK8sInfra(kds)
		}
	}()

	for _, o := range opts {
		o(kds)
	}

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
	kds.runK8sApiserver()

	if kds.k8sApiContainer == nil {
		return nil, errors.New("failed to create k8s API server container")
	}

	log.Info("Started API server")

	start := time.Now()
	for {
		var err error
		kds.K8sClient, err = kubernetes.NewForConfig(&rest.Config{
			Transport: insecureTransport,
			Host:      "https://" + kds.containerGetIPForURL(kds.k8sApiContainer) + ":6443",
			QPS:       100,
			Burst:     100,
		})
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second {
			log.WithError(err).Error("Failed to create k8s client.")
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
			fmt.Sprintf("--server=https://%s:6443", kds.containerGetIPForURL(kds.k8sApiContainer)),
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
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Info("List namespaces successfully.")

	log.Info("Starting controller manager.")
	kds.runK8sControllerManager()
	if kds.k8sControllerManager == nil {
		return nil, errors.New("failed to create k8s controller manager container")
	}

	log.Info("Started controller manager.")

	// Apply CRDs (mounted as docker volume)
	err = kds.k8sApiContainer.ExecMayFail("kubectl", "--kubeconfig=/home/user/certs/kubeconfig", "apply", "-f", "/crds/")
	if err != nil {
		return nil, err
	}

	kds.EndpointIP = kds.containerGetIP(kds.k8sApiContainer)
	kds.Endpoint = fmt.Sprintf("https://%s:6443", kds.containerGetIPForURL(kds.k8sApiContainer))
	kds.BadEndpoint = fmt.Sprintf("https://%s:1234", kds.containerGetIPForURL(kds.k8sApiContainer))

	start = time.Now()
	groupVersion := os.Getenv("CALICO_API_GROUP")
	for {
		var resp *http.Response
		resp, err = insecureHTTPClient.Get(fmt.Sprintf("%s/apis/%s/felixconfigurations", kds.Endpoint, groupVersion))
		if resp.StatusCode != 200 {
			err = fmt.Errorf("bad status (%v) for CRD GET request", resp.StatusCode)
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
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Info("API server is up.")

	kds.CertFileName = "/tmp/" + kds.k8sApiContainer.Name + ".crt"
	start = time.Now()
	for {
		// Make sure any retry is clean.
		_ = os.Remove(kds.CertFileName)

		cmd := utils.Command("docker", "cp",
			kds.k8sApiContainer.Name+":/home/user/certs/kubernetes.pem",
			kds.CertFileName,
		)
		err = cmd.Run()
		if err != nil {
			if time.Since(start) > 120*time.Second {
				log.WithError(err).Error("Failed to get API server cert")
				return nil, err
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Sometimes the very first felix container that we start fails to
		// mount this file.  Double check that it is there and we can read it.
		if _, err := os.Stat(kds.CertFileName); err != nil {
			log.WithError(err).Error("Failed to stat API server cert that we just copied?!")
			if time.Since(start) > 120*time.Second {
				return nil, err
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if f, err := os.Open(kds.CertFileName); err != nil {
			log.WithError(err).Error("Failed to open API server cert that we just copied?!")
			if time.Since(start) > 120*time.Second {
				return nil, err
			}
			time.Sleep(100 * time.Millisecond)
			continue
		} else {
			err := f.Sync()
			if err != nil {
				log.WithError(err).Error("Failed to sync API server cert that we just copied?!")
			}
			_ = f.Close()
		}
		break
	}
	log.Info("Got API server cert.")

	start = time.Now()
	for {
		kds.calicoClient, err = client.New(apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           kds.Endpoint,
					K8sInsecureSkipTLSVerify: true,
					K8sClientQPS:             100,
					CalicoAPIGroup:           os.Getenv("CALICO_API_GROUP"),
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

	// We do run the per-test cleanup stack, this tears down the resources that
	// the test created.
	if ginkgo.CurrentSpecReport().Failed() {
		// Queue up the diags dump so that the cleanupStack will handle any
		// panic from it.
		kds.AddCleanup(kds.DumpErrorData)
	}
	// Run registered teardowns (reverse order). Do not suppress panics.
	defer kds.cleanups.Run()
}

func (kds *K8sDatastoreInfra) AddCleanup(f func()) {
	kds.cleanups.Add(f)
}

func (kds *K8sDatastoreInfra) RegisterFelix(f *Felix) {
	if f == nil {
		return
	}
	kds.felixes = append(kds.felixes, f)
}

type cleanupFunc func(clientset *kubernetes.Clientset, calicoClient client.Interface)

func (kds *K8sDatastoreInfra) CleanUp() {
	log.Info("Cleaning up kubernetes datastore")
	startTime := time.Now()
	cleanupFuncs := []cleanupFunc{
		cleanupAllPods,
		cleanupAllNodes,
		cleanupAllNamespaces,
		cleanupAllPools,
		cleanupIPAM,
		cleanupAllStagedKubernetesNetworkPolicies,
		cleanupAllGlobalNetworkPolicies,
		cleanupAllStagedGlobalNetworkPolicies,
		cleanupAllNetworkPolicies,
		cleanupAllStagedNetworkPolicies,
		cleanupAllTiers,
		cleanupAllHostEndpoints,
		cleanupAllNetworkSets,
		cleanupAllGlobalNetworkSets,
		cleanupAllFelixConfigurations,
		cleanupAllServices,
	}

	for _, f := range cleanupFuncs {
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
		"-e", "KUBERNETES_MASTER=" + kds.Endpoint,
		"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
	}
}

func (kds *K8sDatastoreInfra) GetBadEndpointDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=kubernetes",
		"-e", "FELIX_DATASTORETYPE=kubernetes",
		"-e", "TYPHA_DATASTORETYPE=kubernetes",
		"-e", "K8S_API_ENDPOINT=" + kds.BadEndpoint,
		"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
	}
}

func (kds *K8sDatastoreInfra) GetCalicoClient() client.Interface {
	return kds.calicoClient
}

func (kds *K8sDatastoreInfra) UseProjectCalicoV3API() bool {
	return os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3"
}

func (kds *K8sDatastoreInfra) GetClusterGUID() string {
	ci, err := kds.GetCalicoClient().ClusterInformation().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return ci.Spec.ClusterGUID
}

func (kds *K8sDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, ip string, needBGP bool) {
	felix.ExpectedIPIPTunnelAddr = ip
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedIPIPTunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExpectedVXLANTunnelAddr(felix *Felix, ip string) {
	felix.ExpectedVXLANTunnelAddr = ip
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, ip)
}

func (kds *K8sDatastoreInfra) SetExpectedVXLANV6TunnelAddr(felix *Felix, ip string) {
	felix.ExpectedVXLANV6TunnelAddr = ip
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, ip)
}

func (kds *K8sDatastoreInfra) SetExpectedWireguardTunnelAddr(felix *Felix, cidr *net.IPNet, idx int, needWg bool) {
	// Set to be the same as IPIP tunnel address.
	felix.ExpectedWireguardTunnelAddr = fmt.Sprintf("%d.%d.%d.1", cidr.IP[0], cidr.IP[1], idx)
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedWireguardTunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExpectedWireguardV6TunnelAddr(felix *Felix, cidr *net.IPNet, idx int, needWg bool) {
	// Set to be the same as IPIP tunnel address.
	felix.ExpectedWireguardV6TunnelAddr = net.ParseIP(fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:0",
		cidr.IP[0], cidr.IP[1], cidr.IP[2], cidr.IP[3], cidr.IP[4], cidr.IP[5], cidr.IP[6],
		cidr.IP[7], cidr.IP[8], cidr.IP[9], cidr.IP[10], cidr.IP[11], idx)).String()
	felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedWireguardV6TunnelAddr)
}

func (kds *K8sDatastoreInfra) SetExternalIP(felix *Felix, idx int) {
	if felix.TopologyOptions.EnableIPv6 {
		felix.ExternalIP = fmt.Sprintf("111:222::%d:1", idx)
	} else {
		felix.ExternalIP = fmt.Sprintf("111.222.%d.1", idx)
	}
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

func (kds *K8sDatastoreInfra) AddNode(felix *Felix, v4CIDR *net.IPNet, v6CIDR *net.IPNet, idx int, needBGP bool) {
	nodeIn := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: felix.Hostname,
			Annotations: map[string]string{
				"projectcalico.org/IPv4Address": fmt.Sprintf("%s/%s", felix.IP, felix.IPPrefix),
			},
		},
		Spec: v1.NodeSpec{PodCIDRs: []string{fmt.Sprintf("%d.%d.%d.0/24", v4CIDR.IP[0], v4CIDR.IP[1], idx)}},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{
				Address: felix.IP,
				Type:    v1.NodeInternalIP,
			}},
		},
	}
	if len(felix.IPv6) > 0 && v6CIDR != nil {
		nodeIn.Annotations["projectcalico.org/IPv6Address"] = fmt.Sprintf("%s/%s", felix.IPv6, felix.IPv6Prefix)
		v6CIDR := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%04x::/96", v6CIDR.IP[0], v6CIDR.IP[1], v6CIDR.IP[2], v6CIDR.IP[3], v6CIDR.IP[4], v6CIDR.IP[5], v6CIDR.IP[6], v6CIDR.IP[7], v6CIDR.IP[8], v6CIDR.IP[9], idx)
		// Put the CIDR into canonical format, as required by k8s validation.
		v6CIDR = ip.MustParseCIDROrIP(v6CIDR).String()
		nodeIn.Spec.PodCIDRs = append(nodeIn.Spec.PodCIDRs, v6CIDR)
		nodeIn.Status.Addresses = append(nodeIn.Status.Addresses, v1.NodeAddress{
			Address: felix.IPv6,
			Type:    v1.NodeInternalIP,
		})
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
	if felix.ExpectedVXLANV6TunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv6VXLANTunnelAddr"] = felix.ExpectedVXLANV6TunnelAddr
	}
	if felix.ExpectedWireguardTunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv4WireguardInterfaceAddr"] = felix.ExpectedWireguardTunnelAddr
	}
	if felix.ExpectedWireguardV6TunnelAddr != "" {
		nodeIn.Annotations["projectcalico.org/IPv6WireguardInterfaceAddr"] = felix.ExpectedWireguardV6TunnelAddr
	}
	log.WithField("nodeIn", nodeIn).Debug("Node defined")
	var nodeOut *v1.Node
	var err error
	for i := range 5 {
		nodeOut, err = kds.K8sClient.CoreV1().Nodes().Create(context.Background(), nodeIn, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).WithField("try number", i).Debug("Error creating node")
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		panic(err)
	}
	log.WithField("nodeOut", nodeOut).Debug("Created node")
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

func (kds *K8sDatastoreInfra) AddWorkload(wep *internalapi.WorkloadEndpoint) (*internalapi.WorkloadEndpoint, error) {
	desiredStatus := getPodStatusFromWep(wep)
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

	podIn = updatePodLabelsAndAnnotations(wep, podIn)
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

func (kds *K8sDatastoreInfra) UpdateWorkload(wep *internalapi.WorkloadEndpoint) (*internalapi.WorkloadEndpoint, error) {
	log.WithField("wep", wep).Debug("Updating Pod for workload (labels, annotations and status only)")
	podIn, err := kds.K8sClient.CoreV1().Pods(wep.Namespace).Get(context.Background(), wep.Spec.Workload, metav1.GetOptions{})
	if err != nil {
		panic(err)
	}
	podIn = updatePodLabelsAndAnnotations(wep, podIn)
	podOut, err := kds.K8sClient.CoreV1().Pods(wep.Namespace).Update(context.Background(), podIn, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("podOut", podOut).Debug("Updated pod")
	podIn = podOut
	desiredStatus := getPodStatusFromWep(wep)
	podIn.Status = desiredStatus
	podOut, err = kds.K8sClient.CoreV1().Pods(wep.Namespace).UpdateStatus(context.Background(), podIn, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("podOut", podOut).Debug("Updated pod status")
	return wep, nil
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
			Nets: []string{kds.containerGetIPWithMask(kds.k8sApiContainer)},
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
	policy.Spec.Selector = "all()"
	policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
	_, err := kds.calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	return err
}

func (kds *K8sDatastoreInfra) DumpErrorData() {
	// Per-Felix diagnostics first for context.
	for _, f := range kds.felixes {
		if f != nil {
			dumpFelixDiags(f)
		}
	}

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
	fcs, err := kds.calicoClient.FelixConfigurations().List(context.Background(), options.ListOptions{})
	if err == nil {
		log.Info("DIAGS: Calico FelixConfigurations:")
		for _, fc := range fcs.Items {
			log.Info(spew.Sdump(fc))
		}
	}
}

func (kds *K8sDatastoreInfra) containerGetIPForURL(c *containers.Container) string {
	if kds.ipv6 {
		return "[" + kds.containerGetIP(c) + "]"
	}

	return kds.containerGetIP(c)
}

func (kds *K8sDatastoreInfra) containerGetIPWithMask(c *containers.Container) string {
	return kds.containerGetIP(c) + kds.ipMask
}

func (kds *K8sDatastoreInfra) containerGetIP(c *containers.Container) string {
	if kds.ipv6 {
		return c.IPv6
	}

	return c.IP
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
		if ns.Status.Phase != v1.NamespaceTerminating && !isSystemNamespace(ns.Name) {
			err = clientset.CoreV1().Namespaces().Delete(context.Background(), ns.Name, DeleteImmediately)
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
		err = clientset.CoreV1().Nodes().Delete(context.Background(), node.Name, DeleteImmediately)
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
		nsName := ns.Name
		go func() {
			admission <- 1
			podList, err := clientset.CoreV1().Pods(nsName).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				panic(err)
			}
			log.WithField("count", len(podList.Items)).WithField("namespace", nsName).Debug(
				"Pods present")
			for _, pod := range podList.Items {
				err = clientset.CoreV1().Pods(nsName).Delete(context.Background(), pod.Name, DeleteImmediately)
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

func cleanupAllStagedKubernetesNetworkPolicies(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up Staged kubernetes network policies")
	ctx := context.Background()
	sknps, err := client.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Panic("failed to list staged kubernetes network policies")
	}
	log.WithField("count", len(sknps.Items)).Info("Staged Network Policies present")
	for _, sknp := range sknps.Items {
		_, err = client.StagedKubernetesNetworkPolicies().Delete(ctx, sknp.Namespace, sknp.Name, options.DeleteOptions{})
		if err != nil {
			log.WithError(err).Panicf("failed to delete staged kubernetes network policy %s", sknp.Name)
		}
	}
	log.Info("Cleaned up Staged kubernetes network policies")
}

func cleanupAllStagedGlobalNetworkPolicies(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up Staged GNPs")
	ctx := context.Background()
	sgnps, err := client.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Panic("failed to list staged global network policies")
	}
	log.WithField("count", len(sgnps.Items)).Info("Global Network Policies present")
	for _, sgnp := range sgnps.Items {
		_, err = client.StagedGlobalNetworkPolicies().Delete(ctx, sgnp.Name, options.DeleteOptions{})
		if err != nil {
			log.WithError(err).Panicf("failed to delete staged global network policy %s", sgnp.Name)
		}
	}
	log.Info("Cleaned up Staged GNPs")
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

func cleanupAllStagedNetworkPolicies(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up staged network policies")
	ctx := context.Background()
	snps, err := client.StagedNetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Panic("failed to list staged network policies")
	}
	log.WithField("count", len(snps.Items)).Info("Global Network Policies present")
	for _, snp := range snps.Items {
		_, err = client.StagedNetworkPolicies().Delete(ctx, snp.Namespace, snp.Name, options.DeleteOptions{})
		if err != nil {
			log.WithError(err).Panicf("failed to delete staged network policy %s/%s", snp.Namespace, snp.Name)
		}
	}
	log.Info("Cleaned up staged network policies")
}

func cleanupAllTiers(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up Tiers")
	ctx := context.Background()
	tiers, err := client.Tiers().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Panicf("failed to list tiers")
	}
	log.WithField("count", len(tiers.Items)).Info("Tiers present")
	for _, tier := range tiers.Items {
		if names.TierIsStatic(tier.Name) {
			continue
		}

		_, err = client.Tiers().Delete(ctx, tier.Name, options.DeleteOptions{})
		if err != nil {
			log.WithError(err).Panicf("failed to delete tier %s", tier.Name)
		}
	}
	log.Info("Cleaned up Tiers")
}

func cleanupAllNetworkSets(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up network sets")
	ctx := context.Background()
	ns, err := client.NetworkSets().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(ns.Items)).Info("networksets present")
	for _, n := range ns.Items {
		_, err = client.NetworkSets().Delete(ctx, n.Namespace, n.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up networksets")
}

func cleanupAllGlobalNetworkSets(clientset *kubernetes.Clientset, client client.Interface) {
	log.Info("Cleaning up global network sets")
	ctx := context.Background()
	gns, err := client.GlobalNetworkSets().List(ctx, options.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(gns.Items)).Info("global networksets present")
	for _, gn := range gns.Items {
		_, err = client.GlobalNetworkSets().Delete(ctx, gn.Name, options.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up global network sets")
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
		endpointSliceInterface := clientset.DiscoveryV1().EndpointSlices(ns.Name)
		endpointSlices, err := endpointSliceInterface.List(context.Background(), metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, ep := range endpointSlices.Items {
			if ep.Labels["kubernetes.io/service-name"] == "kubernetes" {
				// Skip cleaning up the Kubernetes API service.
				continue
			}
			err := endpointSliceInterface.Delete(context.Background(), ep.Name, metav1.DeleteOptions{})
			if err != nil && !strings.Contains(err.Error(), "not found") {
				panic(err)
			}
		}
	}
	log.Info("Cleaned up services")
}

func K8sWithServiceClusterIPRange(cidr string) CreateOption {
	return func(ds DatastoreInfra) {
		if kds, ok := ds.(*K8sDatastoreInfra); ok {
			kds.serviceClusterIPRange = cidr
		}
	}
}

func K8sWithAPIServerBindAddress(ip string) CreateOption {
	return func(ds DatastoreInfra) {
		if kds, ok := ds.(*K8sDatastoreInfra); ok {
			kds.apiServerBindIP = ip
		}
	}
}

func K8sWithIPv6() CreateOption {
	return func(ds DatastoreInfra) {
		if kds, ok := ds.(*K8sDatastoreInfra); ok {
			kds.ipv6 = true
			kds.ipMask = "/128"
		}
	}
}

func K8sWithDualStack() CreateOption {
	return func(ds DatastoreInfra) {
		if kds, ok := ds.(*K8sDatastoreInfra); ok {
			kds.ipv6 = true
			kds.dualStack = true
			kds.ipMask = "/128"
		}
	}
}

func getPodStatusFromWep(wep *internalapi.WorkloadEndpoint) v1.PodStatus {
	podIPs := []v1.PodIP{}
	for _, ipnet := range wep.Spec.IPNetworks {
		podIP := strings.Split(ipnet, "/")[0]
		podIP = net.ParseIP(podIP).String() // Normalise the IP.
		podIPs = append(podIPs, v1.PodIP{IP: podIP})
	}
	podStatus := v1.PodStatus{
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
		PodIPs: podIPs,
	}

	return podStatus
}

func updatePodLabelsAndAnnotations(wep *internalapi.WorkloadEndpoint, pod *v1.Pod) *v1.Pod {
	if wep.Labels != nil {
		pod.Labels = wep.Labels
	}
	if wep.Spec.QoSControls != nil {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		if wep.Spec.QoSControls.DSCP != nil {
			pod.Annotations[conversion.AnnotationQoSEgressDSCP] = wep.Spec.QoSControls.DSCP.String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressDSCP)
		}
		if wep.Spec.QoSControls.IngressBandwidth != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressBandwidth] = resource.NewQuantity(wep.Spec.QoSControls.IngressBandwidth, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressBandwidth)
		}
		if wep.Spec.QoSControls.IngressBurst != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressBurst] = resource.NewQuantity(wep.Spec.QoSControls.IngressBurst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressBurst)
		}
		if wep.Spec.QoSControls.IngressPeakrate != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressPeakrate] = resource.NewQuantity(wep.Spec.QoSControls.IngressPeakrate, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressPeakrate)
		}
		if wep.Spec.QoSControls.IngressMinburst != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressMinburst] = resource.NewQuantity(wep.Spec.QoSControls.IngressMinburst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressMinburst)
		}
		if wep.Spec.QoSControls.EgressBandwidth != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressBandwidth] = resource.NewQuantity(wep.Spec.QoSControls.EgressBandwidth, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressBandwidth)
		}
		if wep.Spec.QoSControls.EgressBurst != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressBurst] = resource.NewQuantity(wep.Spec.QoSControls.EgressBurst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressBurst)
		}
		if wep.Spec.QoSControls.EgressPeakrate != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressPeakrate] = resource.NewQuantity(wep.Spec.QoSControls.EgressPeakrate, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressPeakrate)
		}
		if wep.Spec.QoSControls.EgressMinburst != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressMinburst] = resource.NewQuantity(wep.Spec.QoSControls.EgressMinburst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressMinburst)
		}
		if wep.Spec.QoSControls.IngressPacketRate != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressPacketRate] = resource.NewQuantity(wep.Spec.QoSControls.IngressPacketRate, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressPacketRate)
		}
		if wep.Spec.QoSControls.EgressPacketRate != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressPacketRate] = resource.NewQuantity(wep.Spec.QoSControls.EgressPacketRate, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressPacketRate)
		}
		if wep.Spec.QoSControls.IngressPacketBurst != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressPacketBurst] = resource.NewQuantity(wep.Spec.QoSControls.IngressPacketBurst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressPacketBurst)
		}
		if wep.Spec.QoSControls.EgressPacketBurst != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressPacketBurst] = resource.NewQuantity(wep.Spec.QoSControls.EgressPacketBurst, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressPacketBurst)
		}
		if wep.Spec.QoSControls.IngressMaxConnections != 0 {
			pod.Annotations[conversion.AnnotationQoSIngressMaxConnections] = resource.NewQuantity(wep.Spec.QoSControls.IngressMaxConnections, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSIngressMaxConnections)
		}
		if wep.Spec.QoSControls.EgressMaxConnections != 0 {
			pod.Annotations[conversion.AnnotationQoSEgressMaxConnections] = resource.NewQuantity(wep.Spec.QoSControls.EgressMaxConnections, resource.DecimalSI).String()
		} else {
			delete(pod.Annotations, conversion.AnnotationQoSEgressMaxConnections)
		}
	} else if pod.Annotations != nil {
		delete(pod.Annotations, conversion.AnnotationQoSEgressDSCP)
		delete(pod.Annotations, conversion.AnnotationQoSIngressBandwidth)
		delete(pod.Annotations, conversion.AnnotationQoSIngressBurst)
		delete(pod.Annotations, conversion.AnnotationQoSIngressPeakrate)
		delete(pod.Annotations, conversion.AnnotationQoSIngressMinburst)
		delete(pod.Annotations, conversion.AnnotationQoSEgressBandwidth)
		delete(pod.Annotations, conversion.AnnotationQoSEgressBurst)
		delete(pod.Annotations, conversion.AnnotationQoSEgressPeakrate)
		delete(pod.Annotations, conversion.AnnotationQoSEgressMinburst)
		delete(pod.Annotations, conversion.AnnotationQoSIngressPacketRate)
		delete(pod.Annotations, conversion.AnnotationQoSEgressPacketRate)
		delete(pod.Annotations, conversion.AnnotationQoSIngressPacketBurst)
		delete(pod.Annotations, conversion.AnnotationQoSEgressPacketBurst)
		delete(pod.Annotations, conversion.AnnotationQoSIngressMaxConnections)
		delete(pod.Annotations, conversion.AnnotationQoSEgressMaxConnections)

		if len(pod.Annotations) == 0 {
			pod.Annotations = nil
		}
	}
	return pod
}
