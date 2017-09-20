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

package fv_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/k8s-policy/tests/testutils"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/k8s-policy/tests/testutils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

const kubeconfigTemplate = `apiVersion: v1
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

var _ = Describe("PolicyController", func() {
	var (
		etcd             *containers.Container
		policyController *containers.Container
		apiserver        *containers.Container
		calicoClient     *client.Client
		k8sClient        *kubernetes.Clientset
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = GetCalicoClient(etcd.IP)
		err := calicoClient.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kfconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kfconfigfile.Name())
		data := fmt.Sprintf(kubeconfigTemplate, apiserver.IP)
		kfconfigfile.Write([]byte(data))

		policyController = RunPolicyController(etcd.IP, kfconfigfile.Name())

		k8sClient, err = GetK8sClient(kfconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// TODO: Use upcoming port checker functions to wait until apiserver is responding to requests.
		time.Sleep(time.Second * 15)
	})

	It("should create profiles in etcd to represent k8s namespaces", func() {
		// Create the namespace in Kubernetes
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "peanutbutter",
			},
			Spec: v1.NamespaceSpec{},
		}
		_, err := k8sClient.CoreV1().Namespaces().Create(ns)
		Expect(err).NotTo(HaveOccurred())

		// Check that the matching profile was created in etcd.
		Eventually(func() error {
			_, err = calicoClient.Profiles().Get(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
			return err
		}).ShouldNot(HaveOccurred())
	})

	Context("when etcd data is lost", func() {
		BeforeEach(func() {
			// Write some data
			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "peanutbutter",
				},
				Spec: v1.NamespaceSpec{},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(ns)
			Expect(err).NotTo(HaveOccurred())

			// Wait for it to appear in etcd
			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
				return profile
			}).ShouldNot(BeNil())
		})
		It("should recover by rewriting the data to etcd ", func() {
			Stop(apiserver)
			err := calicoClient.Profiles().Delete(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
			Expect(err).ShouldNot(HaveOccurred())

			Start(apiserver)
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})
	})
})
