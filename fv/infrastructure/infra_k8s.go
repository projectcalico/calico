// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"sync"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/options"
)

type K8sDatastoreInfra struct {
	etcdContainer        *containers.Container
	k8sApiContainer      *containers.Container
	k8sControllerManager *containers.Container

	calicoClient client.Interface
	K8sClient    *kubernetes.Clientset

	Endpoint    string
	BadEndpoint string

	CertFileName string
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
	if kds.etcdContainer != nil {
		kds.etcdContainer.Stop()
	}
	if kds.k8sApiContainer != nil {
		kds.k8sApiContainer.Stop()
	}
	if kds.k8sControllerManager != nil {
		kds.k8sControllerManager.Stop()
	}
}

func createK8sDatastoreInfra() DatastoreInfra {
	infra, err := GetK8sDatastoreInfra()
	Expect(err).NotTo(HaveOccurred())
	return infra
}

func GetK8sDatastoreInfra() (*K8sDatastoreInfra, error) {
	if K8sInfra != nil {
		K8sInfra.EnsureReady()
		return K8sInfra, nil
	}

	var err error
	K8sInfra, err = setupK8sDatastoreInfra()
	return K8sInfra, err
}

func runK8sApiserver(etcdIp string) *containers.Container {
	return containers.Run("apiserver",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("PRIVATE_KEY")+":/private.key",
		utils.Config.K8sImage,
		"/hyperkube", "apiserver",
		"--service-cluster-ip-range=10.101.0.0/16",
		"--authorization-mode=RBAC",
		"--insecure-port=8080", // allow insecure connection from controller manager.
		"--insecure-bind-address=0.0.0.0",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdIp),
		"--service-account-key-file=/private.key",
	)
}

func runK8sControllerManager(apiserverIp string) *containers.Container {
	c := containers.Run("controller-manager",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("PRIVATE_KEY")+":/private.key",
		utils.Config.K8sImage,
		"/hyperkube", "controller-manager",
		fmt.Sprintf("--master=%v:8080", apiserverIp),
		"--min-resync-period=3m",
		"--allocate-node-cidrs=true",
		"--cluster-cidr=192.168.0.0/16",
		"--v=5",
		"--service-account-private-key-file=/private.key",
	)
	return c
}

func setupK8sDatastoreInfra() (*K8sDatastoreInfra, error) {
	kds := &K8sDatastoreInfra{}

	// Start etcd, which will back the k8s API server.
	kds.etcdContainer = RunEtcd()
	if kds.etcdContainer == nil {
		return nil, errors.New("failed to create etcd container")
	}

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
		})
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second && err != nil {
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
			"--clusterrole=cluster-admin",
			"--user=system:anonymous",
		)
		if err == nil {
			break
		}
		if time.Since(start) > 90*time.Second && err != nil {
			log.WithError(err).Error("Failed to install role binding")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Info("Added role binding.")

	start = time.Now()
	for {
		_, err := kds.K8sClient.CoreV1().Namespaces().List(metav1.ListOptions{})
		if err == nil {
			break
		}
		if time.Since(start) > 15*time.Second && err != nil {
			log.WithError(err).Error("Failed to list namespaces.")
			TearDownK8sInfra(kds)
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Info("List namespaces successfully.")

	kds.k8sControllerManager = runK8sControllerManager(kds.k8sApiContainer.IP)
	if kds.k8sApiContainer == nil {
		TearDownK8sInfra(kds)
		return nil, errors.New("failed to create k8s contoller manager container")
	}

	log.Info("Started controller manager.")

	// Copy CRD registration manifest into the API server container, and apply it.
	err := kds.k8sApiContainer.CopyFileIntoContainer("../vendor/github.com/projectcalico/libcalico-go/test/crds.yaml", "/crds.yaml")
	if err != nil {
		TearDownK8sInfra(kds)
		return nil, err
	}
	err = kds.k8sApiContainer.ExecMayFail("kubectl", "apply", "-f", "/crds.yaml")
	if err != nil {
		TearDownK8sInfra(kds)
		return nil, err
	}

	kds.Endpoint = fmt.Sprintf("https://%s:6443", kds.k8sApiContainer.IP)
	kds.BadEndpoint = fmt.Sprintf("https://%s:1234", kds.k8sApiContainer.IP)

	start = time.Now()
	for {
		var resp *http.Response
		resp, err = insecureHTTPClient.Get(kds.Endpoint + "/apis/crd.projectcalico.org/v1/globalfelixconfigs")
		if resp.StatusCode != 200 {
			err = errors.New(fmt.Sprintf("Bad status (%v) for CRD GET request", resp.StatusCode))
		}
		if err != nil || resp.StatusCode != 200 {
			log.WithError(err).WithField("status", resp.StatusCode).Warn("Waiting for API server to respond to requests")
		}
		resp.Body.Close()
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second && err != nil {
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
			kds.k8sApiContainer.Name+":/var/run/kubernetes/apiserver.crt",
			kds.CertFileName,
		)
		err = cmd.Run()
		if err == nil {
			break
		}
		if time.Since(start) > 120*time.Second && err != nil {
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
		_, err := kds.K8sClient.CoreV1().ServiceAccounts("default").Get("default", metav1.GetOptions{})
		if err == nil {
			break
		}
		if time.Since(start) > 20*time.Second && err != nil {
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
	cleanupAllPods(kds.K8sClient)
	cleanupAllNodes(kds.K8sClient)
	cleanupAllNamespaces(kds.K8sClient)
	cleanupAllPools(kds.calicoClient)
	cleanupAllGlobalNetworkPolicies(kds.calicoClient)
	cleanupAllNetworkPolicies(kds.calicoClient)
	cleanupAllHostEndpoints(kds.calicoClient)
	cleanupAllFelixConfigurations(kds.calicoClient)
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

func (kds *K8sDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, idx int, needBGP bool) {
	felix.ExpectedIPIPTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
}

func (kds *K8sDatastoreInfra) AddNode(felix *Felix, idx int, needBGP bool) {
	node_in := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: felix.Hostname,
			Annotations: map[string]string{
				"projectcalico.org/IPv4Address": felix.IP,
			},
		},
		Spec: v1.NodeSpec{PodCIDR: fmt.Sprintf("10.65.%d.0/24", idx)},
	}
	if felix.ExpectedIPIPTunnelAddr != "" {
		node_in.Annotations["projectcalico.org/IPv4IPIPTunnelAddr"] = felix.ExpectedIPIPTunnelAddr
	}
	log.WithField("node_in", node_in).Debug("Node defined")
	node_out, err := kds.K8sClient.CoreV1().Nodes().Create(node_in)
	log.WithField("node_out", node_out).Debug("Created node")
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) ensureNamespace(name string) {
	// Try to get namespace. Return if it already exists.
	_, err := kds.K8sClient.CoreV1().Namespaces().Get(name, metav1.GetOptions{})
	if err == nil {
		return
	}

	if !apierrs.IsNotFound(err) {
		panic(err)
	}

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err = kds.K8sClient.CoreV1().Namespaces().Create(ns)
	if err != nil {
		panic(err)
	}
}

func (kds *K8sDatastoreInfra) AddWorkload(wep *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	pod_in := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: wep.Spec.Workload, Namespace: wep.Namespace},
		Spec: v1.PodSpec{Containers: []v1.Container{{
			Name:  wep.Spec.Endpoint,
			Image: "ignore",
		}},
			NodeName: wep.Spec.Node,
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			Conditions: []v1.PodCondition{{
				Type:   v1.PodScheduled,
				Status: v1.ConditionTrue,
			}},
			PodIP: wep.Spec.IPNetworks[0],
		},
	}
	if wep.Labels != nil {
		pod_in.ObjectMeta.Labels = wep.Labels
	}
	log.WithField("pod_in", pod_in).Debug("Pod defined")
	kds.ensureNamespace(wep.Namespace)
	pod_out, err := kds.K8sClient.CoreV1().Pods(wep.Namespace).Create(pod_in)
	if err != nil {
		panic(err)
	}
	log.WithField("pod_out", pod_out).Debug("Created pod")
	pod_in = pod_out
	pod_in.Status.PodIP = wep.Spec.IPNetworks[0]
	pod_out, err = kds.K8sClient.CoreV1().Pods(wep.Namespace).UpdateStatus(pod_in)
	if err != nil {
		panic(err)
	}
	log.WithField("pod_out", pod_out).Debug("Updated pod")

	wepid := names.WorkloadEndpointIdentifiers{
		Node:         wep.Spec.Node,
		Orchestrator: "k8s",
		Endpoint:     wep.Spec.Endpoint,
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

func (kds *K8sDatastoreInfra) AddDefaultAllow() {
	return
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
	nsList, err := kds.K8sClient.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Kubernetes Namespaces\n")
		for _, ns := range nsList.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", ns))
		}
	}

	profiles, err := kds.calicoClient.Profiles().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico Profiles\n")
		for _, profile := range profiles.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", profile))
		}
	}
	policies, err := kds.calicoClient.NetworkPolicies().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico NetworkPolicies\n")
		for _, policy := range policies.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", policy))
		}
	}
	gnps, err := kds.calicoClient.GlobalNetworkPolicies().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico GlobalNetworkPolicies\n")
		for _, gnp := range gnps.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", gnp))
		}
	}
	workloads, err := kds.calicoClient.WorkloadEndpoints().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico WorkloadEndpoints\n")
		for _, w := range workloads.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", w))
		}
	}
	nodes, err := kds.calicoClient.Nodes().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico Nodes\n")
		for _, n := range nodes.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", n))
		}
	}
	heps, err := kds.calicoClient.HostEndpoints().List(context.Background(), options.ListOptions{})
	if err == nil {
		utils.AddToTestOutput("Calico Host Endpoints\n")
		for _, hep := range heps.Items {
			utils.AddToTestOutput(fmt.Sprintf("%v\n", hep))
		}
	}
}

var zeroGracePeriod int64 = 0
var DeleteImmediately = &metav1.DeleteOptions{
	GracePeriodSeconds: &zeroGracePeriod,
}

func isSystemNamespace(ns string) bool {
	return ns == "default" || ns == "kube-system" || ns == "kube-public"
}

func cleanupAllNamespaces(clientset *kubernetes.Clientset) {
	log.Info("Cleaning up all namespaces...")
	nsList, err := clientset.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nsList.Items)).Info("Namespaces present")
	for _, ns := range nsList.Items {
		if ns.Status.Phase != v1.NamespaceTerminating && !isSystemNamespace(ns.ObjectMeta.Name) {
			err = clientset.CoreV1().Namespaces().Delete(ns.ObjectMeta.Name, DeleteImmediately)
			if err != nil {
				panic(err)
			}
		}
	}
	log.Info("Cleaned up all namespaces")
}

func cleanupAllNodes(clientset *kubernetes.Clientset) {
	log.Info("Cleaning up all nodes...")
	nodeList, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nodeList.Items)).Info("Nodes present")
	for _, node := range nodeList.Items {
		err = clientset.CoreV1().Nodes().Delete(node.ObjectMeta.Name, DeleteImmediately)
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up all nodes")
}
func cleanupAllPods(clientset *kubernetes.Clientset) {
	nsList, err := clientset.CoreV1().Namespaces().List(metav1.ListOptions{})
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
			podList, err := clientset.CoreV1().Pods(nsName).List(metav1.ListOptions{})
			if err != nil {
				panic(err)
			}
			log.WithField("count", len(podList.Items)).WithField("namespace", nsName).Debug(
				"Pods present")
			for _, pod := range podList.Items {
				err = clientset.CoreV1().Pods(nsName).Delete(pod.ObjectMeta.Name, DeleteImmediately)
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

func cleanupAllPools(client client.Interface) {
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
}

func cleanupAllGlobalNetworkPolicies(client client.Interface) {
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
}

func cleanupAllNetworkPolicies(client client.Interface) {
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
}

func cleanupAllHostEndpoints(client client.Interface) {
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
}

func cleanupAllFelixConfigurations(client client.Interface) {
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
}
