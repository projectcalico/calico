// Copyright (c) 2017,2019 Tigera, Inc. All rights reserved.
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

// This file contains test utils that are general purpose
// and should one day be moved to a central location for use across all
// projects.

package testutils

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// KubeconfigTemplate is the template used to build a temporary Kubeconfig file for each test
// iteration.
const kubeconfigTemplate = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    insecure-skip-tls-verify: true
    server: https://%s:6443
users:
- name: calico
  user:
    client-certificate-data: %s
    client-key-data: %s
contexts:
- name: test-context
  context:
    cluster: test
    user: calico
current-context: test-context`

func BuildKubeconfig(apiserverIP string) string {
	// Load contents of test cert / key and fill them into the kubeconfig.
	adminCertBytes, err := os.ReadFile(os.Getenv("CERTS_PATH") + "/admin.pem")
	Expect(err).NotTo(HaveOccurred())
	encodedAdminCert := base64.StdEncoding.EncodeToString(adminCertBytes)

	adminKeyBytes, err := os.ReadFile(os.Getenv("CERTS_PATH") + "/admin-key.pem")
	Expect(err).NotTo(HaveOccurred())
	encodedAdminKey := base64.StdEncoding.EncodeToString(adminKeyBytes)

	// Put it all together.
	return fmt.Sprintf(kubeconfigTemplate, apiserverIP, encodedAdminCert, encodedAdminKey)
}

func RunK8sApiserver(etcdIp string) *containers.Container {
	return containers.Run("st-apiserver",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("CERTS_PATH")+":/home/user/certs", // Mount in location of certificates.
		"-v", os.Getenv("CRDS")+":/crds",
		"-e", "KUBECONFIG=/home/user/certs/kubeconfig", // We run kubectl from within this container.
		os.Getenv("KUBE_IMAGE"),
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

func RunK8sControllerManager(apiserverIp string) *containers.Container {
	c := containers.Run("st-controller-manager",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("CERTS_PATH")+":/home/user/certs", // Mount in location of certificates.
		os.Getenv("KUBE_IMAGE"),
		"kube-controller-manager",
		fmt.Sprintf("--master=https://%v:6443", apiserverIp),
		"--cluster-cidr=192.168.0.0/16",
		"--min-resync-period=3m",
		"--kubeconfig=/home/user/certs/kube-controller-manager.kubeconfig",
		// We run trivially small clusters, so increase the QPS to get the
		// cluster to start up as fast as possible.
		"--kube-api-qps=100",
		"--kube-api-burst=200",
		"--min-resync-period=3m",
		"--allocate-node-cidrs=true",
		"--leader-elect=false",
		"--v=5",
		"--service-account-private-key-file=/home/user/certs/service-account-key.pem",
		"--root-ca-file=/home/user/certs/ca.pem",
		"--concurrent-gc-syncs=50",
	)
	return c
}

func RunEtcd() *containers.Container {
	return containers.Run("etcd-fv",
		containers.RunOpts{AutoRemove: true},
		os.Getenv("ETCD_IMAGE"),
		"etcd",
		"--advertise-client-urls", "http://127.0.0.1:2379",
		"--listen-client-urls", "http://0.0.0.0:2379")
}

func GetCalicoClient(dsType apiconfig.DatastoreType, etcdIP, kcfg string) client.Interface {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = dsType
	cfg.Spec.EtcdEndpoints = fmt.Sprintf("http://%s:2379", etcdIP)
	cfg.Spec.Kubeconfig = kcfg
	client, err := client.New(*cfg)

	Expect(err).NotTo(HaveOccurred())
	return client
}

func GetBackendClient(etcdIP string) api.Client {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.EtcdV3
	cfg.Spec.EtcdEndpoints = fmt.Sprintf("http://%s:2379", etcdIP)
	be, err := backend.NewClient(*cfg)

	Expect(err).NotTo(HaveOccurred())
	return be
}

// GetK8sClient gets a kubernetes client.
func GetK8sClient(kubeconfig string) (*kubernetes.Clientset, error) {
	k8sconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	return k8sClientset, nil
}

func Stop(c *containers.Container) {
	var args = []string{"stop", c.Name}
	log.WithField("container", c.Name).Info("Stopping container")
	cmd := exec.Command("docker", args...)
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred())
	out, _ := cmd.CombinedOutput()
	log.Info(out)

}

func Start(c *containers.Container) {
	var args = []string{"start", c.Name}
	log.WithField("container", c.Name).Info("Starting container")
	cmd := exec.Command("docker", args...)
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred())
	out, _ := cmd.CombinedOutput()
	log.Info(out)
}
