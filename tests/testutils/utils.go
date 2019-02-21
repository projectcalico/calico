// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"os/exec"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"

	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const KubeconfigTemplate = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: http://%s:8080
users:
- name: calico
contexts:
- name: test-context
  context:
    cluster: test
    user: calico
current-context: test-context`

func RunK8sApiserver(etcdIp string) *containers.Container {
	return containers.Run("st-apiserver",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("PRIVATE_KEY")+":/private.key",
		"-v", os.Getenv("CRDS_FILE")+":/crds.yaml",
		fmt.Sprintf("%s", os.Getenv("HYPERKUBE_IMAGE")),
		"/hyperkube", "apiserver",
		"--service-cluster-ip-range=10.101.0.0/16",
		"--authorization-mode=AlwaysAllow",
		"--insecure-port=8080",
		"--insecure-bind-address=0.0.0.0",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdIp),
		"--service-account-key-file=/private.key",
	)
}

func RunK8sControllerManager(apiserverIp string) *containers.Container {
	c := containers.Run("st-controller-manager",
		containers.RunOpts{AutoRemove: true},
		"-v", os.Getenv("PRIVATE_KEY")+":/private.key",
		fmt.Sprintf("%s", os.Getenv("HYPERKUBE_IMAGE")),
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

func RunEtcd() *containers.Container {
	return containers.Run("etcd-fv",
		containers.RunOpts{AutoRemove: true},
		fmt.Sprintf("%s", os.Getenv("ETCD_IMAGE")),
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
	log.WithField("container", c.Name).Info("Stopping container")
	args := append([]string{"stop", c.Name})
	cmd := exec.Command("docker", args...)
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred())
	out, _ := cmd.CombinedOutput()
	log.Info(out)

}

func Start(c *containers.Container) {
	log.WithField("container", c.Name).Info("Starting container")
	args := append([]string{"start", c.Name})
	cmd := exec.Command("docker", args...)
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred())
	out, _ := cmd.CombinedOutput()
	log.Info(out)
}
