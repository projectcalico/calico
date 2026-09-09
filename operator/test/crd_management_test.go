// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	//"github.com/operator-framework/operator-sdk/pkg/restmapper"
	corev1 "k8s.io/api/core/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
)

var _ = Describe("CRD management tests", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var npCRD *apiextenv1.CustomResourceDefinition
	var scheme *runtime.Scheme
	var operatorDone chan struct{}

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())
		cfg, err := config.GetConfig()
		Expect(err).NotTo(HaveOccurred())
		c, err = client.New(cfg, client.Options{
			Scheme: scheme,
		})
		Expect(err).NotTo(HaveOccurred())
		verifyCRDsExist(c, operator.Calico)

		// Save the networkpolicies CRD so we can restore it when finished
		npCRD = &apiextenv1.CustomResourceDefinition{
			TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "networkpolicies.crd.projectcalico.org"},
		}

		k := client.ObjectKey{Name: npCRD.Name}
		err = c.Get(context.Background(), k, npCRD)
		Expect(err).NotTo(HaveOccurred())

		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err = c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterEach(func() {
		cleanupResources(c)

		// Clean up Calico data that might be left behind.
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return fmt.Errorf("No nodes found")
			}
			for _, n := range nodes.Items {
				for k := range n.ObjectMeta.Annotations {
					if strings.Contains(k, "projectcalico") {
						delete(n.ObjectMeta.Annotations, k)
					}
				}
				_, err = cs.CoreV1().Nodes().Update(context.Background(), &n, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			}
			return nil
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		mgr = nil

		// Need to make sure the operator is shut down prior to deleting and recreating the networkpolicies CRD otherwise
		// the controller initialized within the tests can recreate the CRD between the deletion confirmation and recreation
		// attempt, creating a timing window where failures can occur.
		cancel()
		Eventually(func() error {
			select {
			case <-operatorDone:
				return nil
			default:
				return fmt.Errorf("operator did not shutdown")
			}
		}, 60*time.Second).Should(BeNil())

		err := c.Delete(context.Background(), npCRD)
		Expect(err).NotTo(HaveOccurred())
		// The "MustPassRepeatedly" here is important because there is some jitter that isn't fully understood that can
		// cause flakes without it
		Eventually(func() error {
			err := GetResource(c, npCRD)
			if kerror.IsNotFound(err) || kerror.IsGone(err) {
				return nil
			} else if err != nil {
				return err
			} else {
				return fmt.Errorf("NetworkPolicy CRD still exists")
			}
		}, 20*time.Second).MustPassRepeatedly(50).ShouldNot(HaveOccurred())
		npCRD.SetResourceVersion("")
		err = c.Create(context.Background(), npCRD)
		Expect(err).NotTo(HaveOccurred())
		ExpectResourceCreated(c, npCRD)
	})

	Describe("Installing CRD", func() {
		BeforeEach(func() {
			// Delete the networkpolicies so we can tell that it gets created.
			err := c.Delete(context.Background(), npCRD)
			Expect(err).NotTo(HaveOccurred())
			ExpectResourceDestroyed(c, npCRD, 10*time.Second)
		})

		It("Should create CRD if it doesn't exist", func() {
			c, shutdownContext, cancel, mgr = setupManager(ManageCRDsEnable, operator.Calico)
			operatorDone = createInstallation(c, mgr, shutdownContext, nil)

			np := npCRD.DeepCopy()
			By("Checking that the networkpolicies CRD is created")
			Eventually(func() error {
				err := GetResource(c, np)
				if err != nil {
					return err
				}
				return nil
			}, 60*time.Second, 1*time.Second).Should(BeNil())
		})
	})

	Describe("Updating CRD", func() {
		BeforeEach(func() {
			edited := npCRD.DeepCopy()
			delete(edited.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties, "tier")
			// Update networkpolicies to ensure it does not include tier.
			err := c.Update(context.Background(), edited)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				err := GetResource(c, edited)
				if err != nil {
					return err
				}
				if _, ok := edited.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["tier"]; ok {
					return fmt.Errorf("NetworkPolicy CRD still has tier")
				}
				return nil
			}, 60*time.Second, 1*time.Second).Should(BeNil())
		})
		It("Should add tier to networkpolicy CRD", func() {
			c, shutdownContext, cancel, mgr = setupManager(ManageCRDsEnable, operator.Calico)
			operatorDone = createInstallation(c, mgr, shutdownContext, nil)

			By("Checking that the networkpolicies CRD is updated with tier")
			Eventually(func() error {
				np := npCRD.DeepCopy()
				err := GetResource(c, np)
				if err != nil {
					return err
				}
				if _, ok := np.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["tier"]; !ok {
					return fmt.Errorf("networkpolicies CRD has not been updated to have tier")
				}
				return nil
			}, 60*time.Second, 1*time.Second).Should(BeNil())
		})
	})
})
