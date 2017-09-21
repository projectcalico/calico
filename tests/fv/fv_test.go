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
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"

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

	Context("profiles", func() {
		var profName string
		BeforeEach(func() {
			nsName := "peanutbutter"
			profName = "k8s_ns." + nsName
			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nsName,
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
				Spec: v1.NamespaceSpec{},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(ns)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
				return profile
			}).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match namespaces in k8s ", func() {
			err := calicoClient.Profiles().Delete(api.ProfileMetadata{Name: profName})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(api.ProfileMetadata{Name: profName})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})
		It("should update existing profiles in etcd to match namespaces in k8s", func() {
			profile, err := calicoClient.Profiles().Update(&api.Profile{Metadata: api.ProfileMetadata{Name: profName}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(profile.Metadata.Labels).To(BeNil())
			Eventually(func() map[string]string {
				prof, _ := calicoClient.Profiles().Get(api.ProfileMetadata{Name: profName})
				return prof.Metadata.Labels
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	Describe("policies", func() {
		var policyName string
		var genPolicyName string

		BeforeEach(func() {
			// Create a Kubernetes NetworkPolicy.
			policyName = "jelly"
			genPolicyName = "knp.default.default." + policyName
			var np *extensions.NetworkPolicy
			np = &extensions.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: "default",
				},
				Spec: extensions.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
				},
			}
			err := k8sClient.Extensions().RESTClient().
				Post().
				Resource("networkpolicies").
				Namespace("default").
				Body(np).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

			// Wait for it to appear in Calico's etcd.
			Eventually(func() *api.Policy {
				policy, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return policy
			}).ShouldNot(BeNil())
		})

		It("should re-write policies in etcd to match policies in k8s", func() {
			// Delete the Policy.
			err := calicoClient.Policies().Delete(api.PolicyMetadata{Name: genPolicyName})
			Expect(err).ShouldNot(HaveOccurred())

			// Wait for the policy-controller to write it back.
			Eventually(func() error {
				_, err := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should re-program policies", func() {
			// Change the selector of the policy in etcd.
			_, err := calicoClient.Policies().Update(&api.Policy{
				Metadata: api.PolicyMetadata{Name: genPolicyName},
				Spec: api.PolicySpec{
					Selector: "calico/k8s_ns == 'default' && ping == 'pong'",
				},
			})
			Expect(err).ShouldNot(HaveOccurred())

			// Wait for the policy-controller to set it back to its original value.
			Eventually(func() string {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return p.Spec.Selector
			}, time.Second*15, 500*time.Millisecond).Should(Equal("calico/k8s_ns == 'default' && fools == 'gold'"))
		})
	})
})
