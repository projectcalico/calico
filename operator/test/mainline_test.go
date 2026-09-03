// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"reflect"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	rconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/internal/controller"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/crds"
	"github.com/projectcalico/calico/operator/pkg/enterprise"
	entcontroller "github.com/projectcalico/calico/operator/pkg/enterprise/controller"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/render"
)

const (
	ManageCRDsEnable  = true
	ManageCRDsDisable = false

	WhiskerCRDExists    = true
	WhiskerCRDNotExists = false

	MultiTenant  = true
	SingleTenant = false
)

var _ = Describe("Mainline component function tests", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}

	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, SingleTenant, operator.Calico)

		By("Cleaning up resources before the test")
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c, operator.CalicoEnterprise)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Checking no Installation is left over from previous tests")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance)
		Expect(kerror.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))
	})

	AfterEach(func() {
		defer func() {
			cancel()

			By("Waiting for operator to shutdown")
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		By("Cleaning up resources after the test")
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
		}, 30*time.Second).Should(BeNil())

		mgr = nil
	})

	It("should recreate resources with DeletionTimestamp set", func() {
		// Reconcile as usual, allowing resources to be created.
		operatorDone = createInstallation(c, mgr, shutdownContext, nil)
		verifyCalicoHasDeployed(c)

		// Delete a resource with a finalizer. This should set the DeletionTimestamp, but leave the
		// resource in place. However, the operator should notice this an recreate the resource, thus
		// clearing the DeletionTimestamp.
		By("Deleting a resource with a finalizer")
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeObjectName, Namespace: common.CalicoNamespace}}
		err := c.Delete(context.Background(), sa)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the resource is recreated")
		Eventually(func() error {
			err := GetResource(c, sa)
			if err != nil {
				return err
			}
			if sa.DeletionTimestamp != nil {
				return fmt.Errorf("ServiceAccount DeletionTimestamp is still set")
			}
			return nil
		}, 10*time.Second).Should(BeNil())
	})

	Describe("Installing CRD", func() {
		It("Should install resources for a CRD", func() {
			operatorDone = createInstallation(c, mgr, shutdownContext, nil)
			verifyCalicoHasDeployed(c)

			instance := &operator.Installation{
				TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			}
			By("Checking that the installation status is set correctly")
			Eventually(func() error {
				err := GetResource(c, instance)
				if err != nil {
					return err
				}
				if instance.Status.Variant != operator.Calico {
					return fmt.Errorf("installation status not Calico yet")
				}
				return nil
			}, 60*time.Second).Should(BeNil())

			By("Checking that the installation status does not change")
			Consistently(func() error {
				err := GetResource(c, instance)
				if err != nil {
					return err
				}
				if reflect.DeepEqual(instance.Status, operator.InstallationStatus{}) {
					return fmt.Errorf("installation status is empty: %+v", instance)
				}
				if instance.Status.Variant != operator.Calico {
					return fmt.Errorf("installation status was %+v, expected: %v", instance.Status, operator.Calico)
				}
				return nil
			}, 30*time.Second, 500*time.Millisecond).Should(BeNil())
		})
	})

	Describe("Deleting CR", func() {
		It("Should delete TigeraStatus for deleted CR", func() {
			instance := &operator.Installation{
				TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			}

			operatorDone = createInstallation(c, mgr, shutdownContext, nil)
			verifyCalicoHasDeployed(c)

			By("Deleting CR after its tigera status becomes available")
			err := c.Delete(context.Background(), instance)
			Expect(err).NotTo(HaveOccurred())
			ExpectResourceDestroyed(c, instance, 20*time.Second)

			By("Verifying the tigera status is removed for deleted CR")
			Eventually(func() error {
				_, err := getTigeraStatus(c, "calico")
				return err
			}, 120*time.Second).ShouldNot(BeNil())
		})
	})
})

var _ = Describe("Mainline component function tests - multi-tenant", func() {
	It("should set up all controllers correctly in multi-tenant mode", func() {
		_, _, cancel, _ := setupManager(ManageCRDsDisable, MultiTenant, operator.CalicoEnterprise)
		cancel()
	})
})

func getTigeraStatus(client client.Client, name string) (*operator.TigeraStatus, error) {
	ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := client.Get(context.TODO(), types.NamespacedName{Name: name}, ts)
	return ts, err
}

func readStatus(ts *operator.TigeraStatus) (available, degraded, progressing bool) {
	for _, condition := range ts.Status.Conditions {
		switch condition.Type {
		case operator.ComponentAvailable:
			available = condition.Status == operator.ConditionTrue
		case operator.ComponentDegraded:
			degraded = condition.Status == operator.ConditionTrue
		case operator.ComponentProgressing:
			progressing = condition.Status == operator.ConditionTrue
		}
	}
	return
}

func assertAvailable(ts *operator.TigeraStatus) error {
	available, degraded, progressing := readStatus(ts)

	if progressing {
		return fmt.Errorf("TigeraStatus is still progressing %v", ts)
	} else if degraded {
		return fmt.Errorf("TigeraStatus is degraded %v", ts)
	} else if !available {
		return fmt.Errorf("TigeraStatus is not available %v", ts)
	}
	return nil
}

func assertDegraded(ts *operator.TigeraStatus) error {
	available, degraded, progressing := readStatus(ts)

	if progressing {
		return fmt.Errorf("TigeraStatus is still progressing %v", ts)
	} else if !degraded {
		return fmt.Errorf("TigeraStatus is not degraded %v", ts)
	} else if available {
		return fmt.Errorf("TigeraStatus is available %v", ts)
	}
	return nil
}

func newNonCachingClient(config *rest.Config, options client.Options) (client.Client, error) {
	options.Cache = nil
	return client.New(config, options)
}

func setupManagerNoControllers() (client.Client, *kubernetes.Clientset, manager.Manager) {
	// Create a Kubernetes client.
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())

	clientset, err := kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	v3CRDs, err := apis.UseV3CRDS(cfg)
	Expect(err).NotTo(HaveOccurred())

	// Create a scheme to use.
	s := runtime.NewScheme()
	err = apis.AddToScheme(s, v3CRDs)
	Expect(err).NotTo(HaveOccurred())

	// Create a manager to use in the tests, providing the scheme we created.
	skipNameValidation := true
	mgr, err := manager.New(cfg, manager.Options{
		Scheme: s,
		Metrics: server.Options{
			BindAddress: "0",
		},
		// Upgrade notes fro v0.14.0 (https://sdk.operatorframework.io/docs/upgrading-sdk-version/version-upgrade-guide/#v014x)
		// say to replace restmapper but the NewDynamicRestMapper did not satisfy the
		// MapperProvider interface
		MapperProvider: apiutil.NewDynamicRESTMapper,
		// Use a non-caching client because we've had issues with flakes in the past where the cache
		// was not updating and tests were failing as a result of looking at stale cluster state
		NewClient: newNonCachingClient,
		Client:    client.Options{},
		Controller: rconfig.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	return mgr.GetClient(), clientset, mgr
}

func setupManager(manageCRDs bool, multiTenant bool, variant operator.ProductVariant) (client.Client, context.Context, context.CancelFunc, manager.Manager) {
	client, clientset, mgr := setupManagerNoControllers()

	// Setup all Controllers
	ctx, cancel := context.WithCancel(context.TODO())
	err := controller.AddToManager(mgr, options.ControllerOptions{
		DetectedProvider: operator.ProviderNone,
		Variant:          variant,
		Extensions:       enterprise.New(variant, eoptions.Options{}),
		Controllers:      entcontroller.Controllers(variant),
		ManageCRDs:       manageCRDs,
		ShutdownContext:  ctx,
		K8sClientset:     clientset,
		MultiTenant:      multiTenant,
	})
	Expect(err).NotTo(HaveOccurred())

	return client, ctx, cancel, mgr
}

func createAPIServer(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.APIServerSpec) {
	s := operator.APIServerSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating an APIServer CRD")
	instance := &operator.APIServer{
		TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       s,
	}
	err := c.Create(context.Background(), instance)
	Expect(err).NotTo(HaveOccurred())
}

func removeAPIServer(ctx context.Context, c client.Client) {
	instance := &operator.APIServer{
		TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	// Use Eventually to handle transient errors.
	exists := true
	Eventually(func() error {
		err := c.Get(ctx, client.ObjectKey{Name: "default"}, instance)
		if err != nil && kerror.IsNotFound(err) {
			exists = false
			return nil
		}
		return err
	}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to get APIServer CR")

	if exists {
		By("Deleting the default APIServer CR")
		Eventually(func() error {
			return c.Delete(ctx, instance)
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to delete APIServer CR")
	}
}

func createInstallation(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.InstallationSpec) (doneChan chan struct{}) {
	s := operator.InstallationSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating an Installation CRD")
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       s,
	}
	err := c.Create(context.Background(), instance)
	Expect(err).NotTo(HaveOccurred())

	By("Running the operator")
	return RunOperator(mgr, ctx)
}

func removeInstallation(ctx context.Context, c client.Client, name string) {
	// Delete any CRD that might have been created by the test.
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}

	// Use Eventually to handle transient errors.
	exists := true
	EventuallyWithOffset(1, func() error {
		err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
		if err != nil && kerror.IsNotFound(err) {
			exists = false
			return nil
		}
		return err
	}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to get Installation CR")

	if exists {
		By("Deleting the Installation CRD")
		EventuallyWithOffset(1, func() error {
			return c.Delete(ctx, instance)
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to delete Installation CR")
	}

	// Need to wait here for Installation resource to be fully deleted prior to cancelling the context
	// which will in turn terminate the operator. Race conditions can occur otherwise that will leave the
	// Installation resource intact while the operator is no longer running which will result in test failures
	// that try to create an Installation resource of their own
	By("Waiting for the Installation CR to be removed")
	EventuallyWithOffset(1, func() error {
		err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
		if kerror.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("Installation still exists")
	}, 120*time.Second).ShouldNot(HaveOccurred(), func() string {
		// Collect debugging information for failure message
		var debugInfo strings.Builder
		debugInfo.WriteString("Installation instance still exists:\n")
		fmt.Fprintf(&debugInfo, "Instance: %+v\n", instance)

		// Get calico-system namespace
		ns := &corev1.Namespace{}
		if err := c.Get(ctx, client.ObjectKey{Name: "calico-system"}, ns); err != nil {
			fmt.Fprintf(&debugInfo, "Failed to get calico-system namespace: %v\n", err)
		} else {
			fmt.Fprintf(&debugInfo, "calico-system namespace: %+v\n", ns)
		}

		// Get all pods in calico-system namespace
		pods := &corev1.PodList{}
		if err := c.List(ctx, pods, client.InNamespace("calico-system")); err != nil {
			fmt.Fprintf(&debugInfo, "Failed to list pods in calico-system namespace: %v\n", err)
		} else {
			fmt.Fprintf(&debugInfo, "Pods in calico-system namespace (%d pods):\n", len(pods.Items))
			for i, pod := range pods.Items {
				fmt.Fprintf(&debugInfo, "  Pod %d: Name=%s, Phase=%s, Ready=%v\n", i+1, pod.Name, pod.Status.Phase, pod.Status.ContainerStatuses)
			}
		}

		return debugInfo.String()
	})
}

func verifyAPIServerHasDeployed(c client.Client) {
	By("Verifying API server was created")
	apiserver := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}}
	ExpectResourceCreated(c, apiserver)

	By("Verifying the API server resources are ready")
	Eventually(func() error {
		err := GetResource(c, apiserver)
		if err != nil {
			return err
		}
		if apiserver.Status.AvailableReplicas >= 1 {
			return nil
		}
		return fmt.Errorf("apiserver not yet ready")
	}, 240*time.Second).Should(BeNil())

	By("Verifying the apiserver tigera status CRD is updated")
	Eventually(func() error {
		ts, err := getTigeraStatus(c, "apiserver")
		if err != nil {
			return err
		}
		return assertAvailable(ts)
	}, 120*time.Second).Should(BeNil())
}

func verifyCalicoHasDeployed(c client.Client) {
	By("Verifying calico-system resources were created")
	ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
	ExpectResourceCreated(c, ds)
	kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
	ExpectResourceCreated(c, kc)

	By("Verifying calico-system resources are ready")
	Eventually(func() error {
		err := GetResource(c, ds)
		if err != nil {
			return err
		}
		if ds.Generation != ds.Status.ObservedGeneration {
			return fmt.Errorf("calico-node status has not observed the latest generation")
		}
		if ds.Status.NumberAvailable == 0 {
			return fmt.Errorf("No node pods running")
		}
		if ds.Status.NumberAvailable == ds.Status.DesiredNumberScheduled {
			return nil
		}
		return fmt.Errorf("Only %d available replicas", ds.Status.NumberAvailable)
	}, 240*time.Second).Should(BeNil())

	Eventually(func() error {
		err := GetResource(c, kc)
		if err != nil {
			return err
		}
		if kc.Status.AvailableReplicas == 1 {
			return nil
		}
		return fmt.Errorf("kube-controllers not yet ready")
	}, 240*time.Second).Should(BeNil())

	By("Verifying the calico tigera status CRD is updated")
	Eventually(func() error {
		ts, err := getTigeraStatus(c, "calico")
		if err != nil {
			return err
		}
		return assertAvailable(ts)
	}, 240*time.Second).Should(BeNil(), "expect calico TigeraStatus to be available")
}

func verifyCRDsExist(c client.Client, variant operator.ProductVariant) {
	crdNames := []string{}
	for _, x := range crds.GetCRDs(variant, false) {
		crdNames = append(crdNames, fmt.Sprintf("%s.%s", x.Spec.Names.Plural, x.Spec.Group))
	}

	// Eventually all the Enterprise CRDs should be available
	EventuallyWithOffset(1, func() error {
		for _, n := range crdNames {
			crd := &apiextensionsv1.CustomResourceDefinition{
				TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: n},
			}
			if err := GetResource(c, crd); err != nil {
				// If getting any of the CRDs is an error then the CRDs do not exist
				return err
			}
		}
		return nil
	}, 10*time.Second).Should(BeNil())
}

func waitForProductTeardown(c client.Client) {
	By("Waiting for Calico resources to be torn down")
	Eventually(func() error {
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		}
		err := GetResource(c, ns)
		if err == nil {
			return fmt.Errorf("Calico namespace still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		crb := &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-node"},
		}
		err = GetResource(c, crb)
		if err == nil {
			return fmt.Errorf("Node CRB still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		defaultInstallation := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = GetResource(c, defaultInstallation)
		if err == nil {
			return fmt.Errorf("default Installation still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		return nil
	}, 240*time.Second).ShouldNot(HaveOccurred(), "Calico resources were not torn down in time")
}

func cleanupIPPools(c client.Client) {
	By("Cleaning up IP pools")
	Eventually(func() error {
		ipPools := &v3.IPPoolList{}
		err := c.List(context.Background(), ipPools)
		if err != nil {
			return err
		}

		for _, p := range ipPools.Items {
			By(fmt.Sprintf("Deleting IP pool %s with CIDR %s (%s)", p.Name, p.Spec.CIDR, p.UID))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
}

func cleanupResources(c client.Client) {
	removeAPIServer(context.Background(), c)
	removeInstallation(context.Background(), c, "default")
	cleanupIPPools(c)
	waitForProductTeardown(c)
}
