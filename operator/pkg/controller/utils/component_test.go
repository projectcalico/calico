// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	stderrors "errors"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ocsv1 "github.com/openshift/api/security/v1"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	restMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
)

const (
	fakeComponentAnnotationKey   = "tigera.io/annotation-should-be"
	fakeComponentAnnotationValue = "present"
	fakeComponentLabelKey        = "tigera.io/label-should-be"
	fakeComponentLabelValue      = "labelvalue"
)

var _ = Describe("Component handler tests", func() {
	var (
		c        client.Client
		instance *operatorv1.APIServer
		ctx      context.Context
		scheme   *runtime.Scheme
		sm       status.StatusManager
		handler  ComponentHandler
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		sm = status.New(c, "fake-component", &common.VersionInfo{Major: 1, Minor: 19})

		// We need to provide something to handler even though it seems to be unused..
		instance = &operatorv1.APIServer{
			TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		handler = NewComponentHandler(logf.Log, c, scheme, instance)
	})

	It("respects NetworkPolicy.ManagePolicies setting in Installation", func() {
		// Create an Installation resource with networkPolicy.managePolicies: Disabled.
		disabled := operatorv1.NetworkPolicyManagementDisabled
		install := &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				NetworkPolicy: &operatorv1.NetworkPolicySpec{ManagePolicies: &disabled},
			},
		}
		install.Status.Computed = install.Spec.DeepCopy()
		Expect(c.Create(ctx, install)).To(BeNil())

		// Create a component that returns a NetworkPolicy and a Deployment.
		np := &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		}
		dep := &apps.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "test-dep", Namespace: "default"},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{np, dep},
		}

		// Reconcile the component.
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		// Verify that the Deployment was created, but the NetworkPolicy was not.
		err = c.Get(ctx, client.ObjectKey{Name: "test-dep", Namespace: "default"}, &apps.Deployment{})
		Expect(err).To(BeNil())

		err = c.Get(ctx, client.ObjectKey{Name: "test-policy", Namespace: "default"}, &v3.NetworkPolicy{})
		Expect(errors.IsNotFound(err)).To(BeTrue())

		// Now enable management and reconcile again.
		enabled := operatorv1.NetworkPolicyManagementEnabled
		install.Spec.NetworkPolicy = &operatorv1.NetworkPolicySpec{ManagePolicies: &enabled}
		Expect(c.Update(ctx, install)).To(BeNil())
		install.Status.Computed = install.Spec.DeepCopy()
		Expect(c.Status().Update(ctx, install)).To(BeNil())

		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		// Verify that the NetworkPolicy was created.
		err = c.Get(ctx, client.ObjectKey{Name: "test-policy", Namespace: "default"}, &v3.NetworkPolicy{})
		Expect(err).To(BeNil())

		// Now disable management again and verify that the policy is deleted.
		install.Spec.NetworkPolicy = &operatorv1.NetworkPolicySpec{ManagePolicies: &disabled}
		Expect(c.Update(ctx, install)).To(BeNil())
		install.Status.Computed = install.Spec.DeepCopy()
		Expect(c.Status().Update(ctx, install)).To(BeNil())

		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		err = c.Get(ctx, client.ObjectKey{Name: "test-policy", Namespace: "default"}, &v3.NetworkPolicy{})
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})

	It("adds Owner references when Custom Resource is provided", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		dsKey := client.ObjectKey{
			Name:      "test-ds",
			Namespace: "default",
		}
		ds := &apps.DaemonSet{}
		_ = c.Get(ctx, dsKey, ds)
		Expect(ds.OwnerReferences).To(HaveLen(1))
		t := true
		expectOR := metav1.OwnerReference{
			APIVersion:         "operator.tigera.io/v1",
			Kind:               "APIServer",
			Name:               "default",
			Controller:         &t,
			BlockOwnerDeletion: &t,
		}
		Expect(ds.OwnerReferences[0]).To(Equal(expectOR))
	})

	It("doesn't remove finalizers it doesn't own", func() {
		// Create a daemonset with a finalizer that the operator doesn't own.
		ds := &apps.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-ds",
				Namespace:  "default",
				Finalizers: []string{"some.finalizer.io/do-not-remove"},
			},
			Spec: apps.DaemonSetSpec{},
		}
		err := c.Create(ctx, ds)
		Expect(err).To(BeNil())

		// Trigger an update to reconcile, but without the finalizer present in the desired state.
		ds.Finalizers = []string{}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{ds},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		// Get the updated daemonset and verify the finalizer is still present.
		updatedDS := &apps.DaemonSet{}
		err = c.Get(ctx, client.ObjectKey{Name: "test-ds", Namespace: "default"}, updatedDS)
		Expect(err).To(BeNil())
		Expect(updatedDS.Finalizers).To(ContainElement("some.finalizer.io/do-not-remove"))
	})

	It("merges daemonset template annotations and reconciles only operator added annotations", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the daemonset is created and desired annotations are present")
		expectedAnnotations := map[string]string{
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		dsKey := client.ObjectKey{
			Name:      "test-ds",
			Namespace: "default",
		}
		ds := &apps.DaemonSet{}
		_ = c.Get(ctx, dsKey, ds)
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(expectedAnnotations))

		By("add a new annotation, simulating a rolling restart request")
		annotations := map[string]string{
			fakeComponentAnnotationKey:          fakeComponentAnnotationValue,
			"kubectl.kubernetes.io/restartedAt": "some-time",
		}
		ds.Spec.Template.Annotations = annotations
		Expect(c.Update(ctx, ds)).NotTo(HaveOccurred())

		By("checking that the object is updated with the annotation")
		ds = &apps.DaemonSet{}
		err = c.Get(ctx, dsKey, ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(annotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		By("initiating a merge")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the daemonset and checking that both current and desired annotations are still present")
		expectedAnnotations = map[string]string{
			fakeComponentAnnotationKey:          fakeComponentAnnotationValue,
			"kubectl.kubernetes.io/restartedAt": "some-time",
		}
		ds = &apps.DaemonSet{}
		err = c.Get(ctx, dsKey, ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(expectedAnnotations))
	})

	It("merges annotations and reconciles only operator added annotations", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the namespace is created and desired annotations is present")
		expectedAnnotations := map[string]string{
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		nsKey := client.ObjectKey{
			Name: "test-namespace",
		}
		ns := &corev1.Namespace{}
		_ = c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("ovewriting the namespace with SCC annotations")
		annotations := map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		ns.Annotations = annotations
		Expect(c.Update(ctx, ns)).NotTo(HaveOccurred())

		By("checking that the namespace is updated with SCC annotation")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		By("initiating a merge with Openshift SCC annotations")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that both current and desired annotations are still present")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("changing a desired annotation")
		annotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			"cattle-not-pets":          "indeed",
			fakeComponentAnnotationKey: "not-present",
		}
		ns.Annotations = annotations
		err = c.Update(ctx, ns)
		Expect(err).To(BeNil())

		By("checking that the namespace is updated with new modified annotation")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: "not-present",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		By("initiating a merge with namespace containing modified desired annotation")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that desired annotation is reconciled, everything else is left as-is")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))
	})

	It("merges labels and reconciles only operator added labels", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the namespace is created and desired label is present")
		expectedLabels := map[string]string{
			fakeComponentLabelKey:          fakeComponentLabelValue,
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/part-of":    "Calico",
			"app.kubernetes.io/name":       "test-namespace",
			"k8s-app":                      "test-namespace",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
		}
		nsKey := client.ObjectKey{
			Name: "test-namespace",
		}
		ns := &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		By("ovewriting the namespace with extra label")
		labels := map[string]string{
			"extra": "extra-value",
		}
		ns.Labels = labels
		Expect(c.Update(ctx, ns)).NotTo(HaveOccurred())

		By("checking that the namespace is updated with extra label")
		expectedLabels = map[string]string{
			"extra": "extra-value",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		By("initiating a merge with extra label")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that both current and desired labels are still present")
		expectedLabels = map[string]string{
			"extra":                        "extra-value",
			fakeComponentLabelKey:          fakeComponentLabelValue,
			"k8s-app":                      "test-namespace",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "test-namespace",
			"app.kubernetes.io/part-of":    "Calico",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		By("changing a desired label")
		labels = map[string]string{
			"extra":                        "extra-value",
			"cattle-not-pets":              "indeed",
			fakeComponentLabelKey:          "not-present",
			"app.kubernetes.io/part-of":    "Calico",
			"k8s-app":                      "test-namespace",
			"app.kubernetes.io/name":       "test-namespace",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/instance":   "default",
		}
		ns.Labels = labels
		err = c.Update(ctx, ns)
		Expect(err).To(BeNil())

		By("checking that the namespace is updated with new modified label")
		expectedLabels = map[string]string{
			"cattle-not-pets":              "indeed",
			"extra":                        "extra-value",
			fakeComponentLabelKey:          "not-present",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "test-namespace",
			"app.kubernetes.io/part-of":    "Calico",
			"k8s-app":                      "test-namespace",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		By("initiating a merge with namespace containing modified desired label")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that desired label is reconciled, everything else is left as-is")
		expectedLabels = map[string]string{
			"cattle-not-pets":              "indeed",
			"extra":                        "extra-value",
			fakeComponentLabelKey:          fakeComponentLabelValue,
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "test-namespace",
			"k8s-app":                      "test-namespace",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/part-of":    "Calico",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))
	})

	It("skips the per-owner instance and component labels on objects shared by multiple owners", func() {
		// A shared object is written by more than one controller, each passing its own CR.
		// The instance and component labels identify the writing CR, so stamping them would
		// flip the values with every writer and the object would be rewritten on every
		// reconcile. The writer-independent labels are still applied.
		sharedRoleBinding := func() *rbacv1.RoleBinding {
			return &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shared-rolebinding",
					Namespace: "test-namespace",
					Labels:    map[string]string{common.MultipleOwnersLabel: "true"},
				},
			}
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{sharedRoleBinding()},
		}

		Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

		rbKey := client.ObjectKey{Namespace: "test-namespace", Name: "shared-rolebinding"}
		rb := &rbacv1.RoleBinding{}
		Expect(c.Get(ctx, rbKey, rb)).To(BeNil())
		Expect(rb.GetLabels()).To(Equal(map[string]string{
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "shared-rolebinding",
			"app.kubernetes.io/part-of":    "Calico",
			"k8s-app":                      "shared-rolebinding",
		}))

		By("leaving an instance label stamped by an earlier writer as it is")
		rb.Labels["app.kubernetes.io/instance"] = "some-other-owner"
		Expect(c.Update(ctx, rb)).NotTo(HaveOccurred())

		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{sharedRoleBinding()},
		}
		Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

		rb = &rbacv1.RoleBinding{}
		Expect(c.Get(ctx, rbKey, rb)).To(BeNil())
		Expect(rb.GetLabels()).To(HaveKeyWithValue("app.kubernetes.io/instance", "some-other-owner"))
		Expect(rb.GetLabels()).NotTo(HaveKey("app.kubernetes.io/component"))
		Expect(rb.GetLabels()).NotTo(HaveKey(common.MultipleOwnersLabel))
	})

	Context("ensureTLSCiphers", func() {
		cipher1 := operatorv1.TLS_AES_128_GCM_SHA256
		cipher2 := operatorv1.TLS_AES_256_GCM_SHA384
		cipherList := operatorv1.TLSCipherSuites{
			operatorv1.TLSCipherSuite{Name: &cipher1},
			operatorv1.TLSCipherSuite{Name: &cipher2},
		}
		ciphersToString := fmt.Sprintf("%s,%s", cipher1, cipher2)
		DescribeTable("ensuring TLS Ciphers are set properly",
			func(obj client.Object, installationCiphers operatorv1.TLSCipherSuites, expectedEnvVar string) {
				installation := &operatorv1.Installation{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "default",
						Generation: 2,
					},
					Spec: operatorv1.InstallationSpec{
						TLSCipherSuites: installationCiphers,
					},
				}
				Expect(c.Create(ctx, installation)).To(BeNil())
				Expect(ensureTLSCiphers(obj, &installation.Spec)).To(BeNil())

				var containers []corev1.Container
				switch o := obj.(type) {
				case *apps.Deployment:
					containers = o.Spec.Template.Spec.Containers
				case *apps.DaemonSet:
					containers = o.Spec.Template.Spec.Containers
				}

				for _, c := range containers {
					envVarFound := false
					for _, envVar := range c.Env {
						if envVar.Name == TLS_CIPHERS_ENV_VAR_NAME {
							Expect(envVar.Value).To(Equal(expectedEnvVar))
							return
						}
					}
					Expect(envVarFound).To(Equal(expectedEnvVar != ""), "%s env var not found in container %s", TLS_CIPHERS_ENV_VAR_NAME, c.Name)
				}
			},
			Entry("set TLS Ciphers on a DaemonSet",
				&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Image: "foo"}, {Image: "bar"}},
							},
						},
					},
				},
				cipherList,
				ciphersToString,
			),
			Entry("set TLS Ciphers on a Deployment",
				&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Image: "foo"}, {Image: "bar"}},
							},
						},
					},
				},
				cipherList,
				ciphersToString,
			),
			Entry("set TLS Ciphers env var explicitly in the object",
				&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Image: "foo",
										Env: []corev1.EnvVar{
											{
												Name:  TLS_CIPHERS_ENV_VAR_NAME,
												Value: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
											},
										},
									},
								},
							},
						},
					},
				},
				cipherList,
				string(operatorv1.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
			),
			Entry("empty TLS Ciphers configuration",
				&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Image: "foo"}},
							},
						},
					},
				},
				nil,
				"",
			),
		)
	})
	DescribeTable("ensuring ImagePullPolicy is set", func(obj client.Object) {
		modifyPodSpec(obj, func(p *corev1.PodSpec) { setImagePullPolicy(p, nil) })

		switch o := obj.(type) {
		case *apps.Deployment:
			for _, c := range o.Spec.Template.Spec.Containers {
				Expect(c.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
			}
		case *apps.DaemonSet:
			for _, c := range o.Spec.Template.Spec.Containers {
				Expect(c.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
			}
		default:
			Expect(true).To(Equal(false), "Unexpected kind in test")
		}
	},
		Entry("set ImagePullPolicy on a DaemonSet",
			&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							NodeSelector: map[string]string{},
							Containers: []corev1.Container{
								{Image: "foo"},
								{Image: "bar"},
							},
						},
					},
				},
			},
		),
		Entry("set ImagePullPolicy on a Deployment",
			&apps.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
				Spec: apps.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							NodeSelector: map[string]string{},
							Containers: []corev1.Container{
								{Image: "foo"},
								{Image: "bar"},
							},
						},
					},
				},
			},
		),
	)

	Describe("setImagePullPolicy", func() {
		It("fills missing policies with IfNotPresent and leaves explicit policies alone when no policy is configured", func() {
			ps := &corev1.PodSpec{
				Containers:     []corev1.Container{{Image: "a"}, {Image: "b", ImagePullPolicy: corev1.PullAlways}},
				InitContainers: []corev1.Container{{Image: "init"}},
			}
			setImagePullPolicy(ps, nil)
			Expect(ps.Containers[0].ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
			Expect(ps.Containers[1].ImagePullPolicy).To(Equal(corev1.PullAlways), "should not override an explicitly set policy")
			Expect(ps.InitContainers[0].ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		})

		It("overrides every container's policy when a policy is configured on the Installation", func() {
			ps := &corev1.PodSpec{
				Containers:     []corev1.Container{{Image: "a"}, {Image: "b", ImagePullPolicy: corev1.PullAlways}},
				InitContainers: []corev1.Container{{Image: "init", ImagePullPolicy: corev1.PullAlways}},
			}
			setImagePullPolicy(ps, ptr.To(corev1.PullNever))
			Expect(ps.Containers[0].ImagePullPolicy).To(Equal(corev1.PullNever))
			Expect(ps.Containers[1].ImagePullPolicy).To(Equal(corev1.PullNever), "configured policy must win over renderer defaults")
			Expect(ps.InitContainers[0].ImagePullPolicy).To(Equal(corev1.PullNever))
		})
	})

	DescribeTable("ensuring os node selectors", func(component render.Component, key client.ObjectKey, obj client.Object, expectedNodeSelectors map[string]string) {
		Expect(handler.CreateOrUpdateOrDelete(ctx, component, sm)).ShouldNot(HaveOccurred())
		Expect(c.Get(ctx, key, obj)).ShouldNot(HaveOccurred())

		var nodeSelectors map[string]string
		switch x := obj.(type) {
		case *corev1.PodTemplate:
			nodeSelectors = x.Template.Spec.NodeSelector
		case *apps.Deployment:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *apps.DaemonSet:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *apps.StatefulSet:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *batchv1.CronJob:
			nodeSelectors = x.Spec.JobTemplate.Spec.Template.Spec.NodeSelector
		case *batchv1.Job:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *kbv1.Kibana:
			nodeSelectors = x.Spec.PodTemplate.Spec.NodeSelector
		case *esv1.Elasticsearch:
			// elasticsearch resource describes multiple nodeSets which each have a nodeSelector.
			nodeSets := x.Spec.NodeSets
			for _, ns := range nodeSets {
				Expect(ns.PodTemplate.Spec.NodeSelector).Should(Equal(expectedNodeSelectors))
			}
			return
		case *monitoringv1.Alertmanager:
			nodeSelectors = x.Spec.NodeSelector
		case *monitoringv1.Prometheus:
			nodeSelectors = x.Spec.NodeSelector
		default:
			Expect(fmt.Errorf("unexpected type passed to test")).ToNot(HaveOccurred())
		}

		Expect(nodeSelectors).Should(Equal(expectedNodeSelectors))
	},
		Entry("linux - sets the required annotations for a podtemplate when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&corev1.PodTemplate{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							NodeSelector: map[string]string{},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-podtemplate"},
			&corev1.PodTemplate{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a podtemplate when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{&corev1.PodTemplate{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							NodeSelector: map[string]string{},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-podtemplate"},
			&corev1.PodTemplate{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("linux - sets the required annotations for a deployment when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-deployment"},
			&apps.Deployment{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a deployment when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-deployment"},
			&apps.Deployment{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("linux - sets the required annotations for a daemonset when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-daemonset"},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-daemonset"},
			&apps.DaemonSet{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a daemonset when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{
					&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-daemonset"},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-daemonset"},
			&apps.DaemonSet{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("linux - sets the required annotations for a statefulset when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.StatefulSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset"},
						Spec: apps.StatefulSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-statefulset"},
			&apps.StatefulSet{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a statefulset when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{
					&apps.StatefulSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset"},
						Spec: apps.StatefulSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-statefulset"},
			&apps.StatefulSet{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("linux - sets the required annotations for a cronjob when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&batchv1.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1.CronJobSpec{
							JobTemplate: batchv1.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-cronjob"},
			&batchv1.CronJob{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a cronjob when they're not set",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{
					&batchv1.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1.CronJobSpec{
							JobTemplate: batchv1.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						},
					},
				},
			},
			client.ObjectKey{Name: "test-cronjob"},
			&batchv1.CronJob{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("linux - sets the required annotations for a job",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-job"},
			&batchv1.Job{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("windows - sets the required annotations for a job",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{&batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-job"},
			&batchv1.Job{},
			map[string]string{
				"kubernetes.io/os": "windows",
			},
		),
		Entry("sets the required annotations for kibana",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&kbv1.Kibana{
					ObjectMeta: metav1.ObjectMeta{Name: "test-kibana"},
					Spec: kbv1.KibanaSpec{
						PodTemplate: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-kibana"},
			&kbv1.Kibana{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("sets the required annotations for an elasticsearch nodeset",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&esv1.Elasticsearch{
					ObjectMeta: metav1.ObjectMeta{Name: "test-elasticsearch"},
					Spec: esv1.ElasticsearchSpec{
						NodeSets: []esv1.NodeSet{
							{
								PodTemplate: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										NodeSelector: map[string]string{},
									},
								},
							},
							{
								PodTemplate: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										NodeSelector: nil,
									},
								},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-elasticsearch"},
			&esv1.Elasticsearch{},
			map[string]string{
				"kubernetes.io/os": "linux",
			},
		),
		Entry("linux - leaves other annotations alone and sets the required ones",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/foo": "bar",
								},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-deployment"},
			&apps.Deployment{},
			map[string]string{
				"kubernetes.io/foo": "bar",
				"kubernetes.io/os":  "linux",
			},
		),
		Entry("windows - leaves other annotations alone and sets the required ones",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeWindows,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/foo": "bar",
								},
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-deployment"},
			&apps.Deployment{},
			map[string]string{
				"kubernetes.io/foo": "bar",
				"kubernetes.io/os":  "windows",
			},
		),
		Entry("linux - sets the required annotations for Prometheus Alertmanager nodes",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&monitoringv1.Alertmanager{
					ObjectMeta: metav1.ObjectMeta{Name: "test-alertmanager"},
					Spec: monitoringv1.AlertmanagerSpec{
						NodeSelector: map[string]string{
							"kubernetes.io/a": "b",
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-alertmanager"},
			&monitoringv1.Alertmanager{},
			map[string]string{
				"kubernetes.io/a":  "b",
				"kubernetes.io/os": "linux",
			},
		),
		Entry("linux - sets the required annotations for Prometheus nodes",
			&fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&monitoringv1.Prometheus{
					ObjectMeta: metav1.ObjectMeta{Name: "test-prometheus"},
					Spec: monitoringv1.PrometheusSpec{
						CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
							NodeSelector: map[string]string{
								"kubernetes.io/a": "b",
							},
						},
					},
				}},
			},
			client.ObjectKey{Name: "test-prometheus"},
			&monitoringv1.Prometheus{},
			map[string]string{
				"kubernetes.io/a":  "b",
				"kubernetes.io/os": "linux",
			},
		),
	)

	It("recreates a service if its ClusterIP is removed", func() {
		// Simulate creation of a service by earlier version of operator that includes a ClusterIP.
		svcWithIP := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-service",
				Labels: map[string]string{
					"old":                          "should-be-preserved",
					"app.kubernetes.io/instance":   "default",
					"app.kubernetes.io/managed-by": "tigera-operator",
					"app.kubernetes.io/name":       "my-service",
					"app.kubernetes.io/part-of":    "Calico",
					"k8s-app":                      "my-service",
					"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
				},
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.96.0.1",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				svcWithIP,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcWithIP)).NotTo(HaveOccurred())
		Expect(svcWithIP.Spec.ClusterIP).To(Equal("10.96.0.1"))
		Expect(svcWithIP.Labels).To(Equal(map[string]string{
			"old":                          "should-be-preserved",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "my-service",
			"app.kubernetes.io/part-of":    "Calico",
			"k8s-app":                      "my-service",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
		}))

		// Now pretend we're the new operator version, wanting to remove the cluster IP.
		svcNoIP := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-service",
				Labels: map[string]string{
					"new": "should-be-added",
				},
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "None",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				svcNoIP,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcNoIP)).NotTo(HaveOccurred())
		Expect(svcNoIP.Spec.ClusterIP).To(Equal("None"))
		Expect(svcNoIP.Labels).To(Equal(map[string]string{
			"old":                          "should-be-preserved",
			"new":                          "should-be-added",
			"k8s-app":                      "my-service",
			"app.kubernetes.io/name":       "my-service",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/part-of":    "Calico",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
		}))

		// The fake client resets the resource version to 1 on create.
		Expect(svcNoIP.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of Service to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update.
		svcNoIP.Labels = map[string]string{"newer": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcNoIP)).NotTo(HaveOccurred())
		Expect(svcNoIP.Labels).To(Equal(map[string]string{
			"old":                          "should-be-preserved",
			"new":                          "should-be-added",
			"newer":                        "should-be-added",
			"k8s-app":                      "my-service",
			"app.kubernetes.io/instance":   "default",
			"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			"app.kubernetes.io/managed-by": "tigera-operator",
			"app.kubernetes.io/name":       "my-service",
			"app.kubernetes.io/part-of":    "Calico",
		}))
		Expect(svcNoIP.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update to rev ResourceVersion")
	})

	It("allows you to replace a secret if the types change", func() {
		// Please note that a fake client does not behave exactly as it would on K8s:
		// - A secret without a type in a real cluster automatically becomes type Opaque
		// - An update where the secret type changes would be rejected in a real cluster, yet the fake client accepts it.
		// This test serves to purpose of at least verifying that an update of a secret type works without error.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret"},
			Type:       corev1.SecretTypeOpaque,
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				secret,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-secret"}, secret)).NotTo(HaveOccurred())
		Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
		secret.Type = corev1.SecretTypeTLS
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-secret"}, secret)).NotTo(HaveOccurred())
		Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
	})

	It("recreates a RoleBinding if roleRef changes", func() {
		// In a real cluster we get an error if we attempt to update an existing RoleBinding's RoleRef field because
		// it is immutable. We can't properly check that update isn't called here because the fake client we use
		// doesn't contain validation logic like that, so it will happily perform an update that would be rejected in
		// a real cluster. As an indirect way to check that we're running our code that performs a delete/create instead
		// of an update, we check the resource version of the RoleBinding after the create. If it's 1, we know it was
		// deleted and recreated
		rbOldRoleRef := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-rolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "old-roleref",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				rbOldRoleRef,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbOldRoleRef)).NotTo(HaveOccurred())
		Expect(rbOldRoleRef.RoleRef.Name).To(Equal("old-roleref"))

		// Now pretend we're the new operator version, wanting to change the name of the roleRef.
		rbNewRoleRef := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-rolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "new-roleref",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				rbNewRoleRef,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbNewRoleRef)).NotTo(HaveOccurred())
		Expect(rbNewRoleRef.RoleRef.Name).To(Equal("new-roleref"))

		// The fake client resets the resource version to 1 on create.
		Expect(rbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of RoleBinding to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update rather than a delete/create
		rbNewRoleRef.Labels = map[string]string{"new": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbNewRoleRef)).NotTo(HaveOccurred())
		Expect(rbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update of RoleBinding to rev resourceversion to 2")
	})

	It("recreates a ClusterRoleBinding if roleRef changes", func() {
		// In a real cluster we get an error if we attempt to update an existing ClusterRoleBinding's RoleRef field because
		// it is immutable. We can't properly check that update isn't called here because the fake client we use
		// doesn't contain validation logic like that, so it will happily perform an update that would be rejected in
		// a real cluster. As an indirect way to check that we're running our code that performs a delete/create instead
		// of an update, we check the resource version of the ClusterRoleBinding after the create. If it's 1, we know it was
		// deleted and recreated
		crbOldRoleRef := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-clusterrolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "old-roleref",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				crbOldRoleRef,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbOldRoleRef)).NotTo(HaveOccurred())
		Expect(crbOldRoleRef.RoleRef.Name).To(Equal("old-roleref"))

		// Now pretend we're the new operator version, wanting to change the name of the roleRef.
		crbNewRoleRef := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-clusterrolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "new-roleref",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				crbNewRoleRef,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbNewRoleRef)).NotTo(HaveOccurred())
		Expect(crbNewRoleRef.RoleRef.Name).To(Equal("new-roleref"))

		// The fake client resets the resource version to 1 on create.
		Expect(crbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of ClusterRoleBinding to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update rather than a delete/create
		crbNewRoleRef.Labels = map[string]string{"new": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbNewRoleRef)).NotTo(HaveOccurred())
		Expect(crbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update of ClusterRoleBinding to rev resourceversion to 2")
	})

	Context("with a terminating Namespace", func() {
		var ns *corev1.Namespace
		BeforeEach(func() {
			// Create a Namespace with a finalizer to make sure it is not immediately deleted.
			ns = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-namespace",
					Finalizers: []string{"test-finalizer"},
				},
			}
			Expect(c.Create(ctx, ns)).To(Succeed())

			// Delete the Namespace to put it in the terminating state.
			Expect(c.Get(ctx, client.ObjectKey{Name: ns.Name}, ns)).To(Succeed())
			Expect(c.Delete(ctx, ns)).To(Succeed())
			Expect(c.Get(ctx, client.ObjectKey{Name: ns.Name}, ns)).To(Succeed())
			Expect(ns.DeletionTimestamp).NotTo(BeNil())
		})

		AfterEach(func() {
			// Remove finalizers from the Namespace to allow it to be deleted.
			ns.Finalizers = nil
			Expect(c.Update(ctx, ns)).To(Succeed())
			Expect(c.Get(ctx, client.ObjectKey{Name: ns.Name}, ns)).NotTo(Succeed())
		})

		It("does not attempt to create resources in a terminating Namespace", func() {
			// Create a ConfigMap in the terminating Namespace.
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: ns.Name,
				},
			}

			// Shouldn't return an error, but also shouldn't create the ConfigMap.
			Expect(handler.CreateOrUpdateOrDelete(
				ctx,
				&fakeComponent{objs: []client.Object{cm}, supportedOSType: rmeta.OSTypeLinux},
				sm,
			)).NotTo(HaveOccurred())

			// The ConfigMap should not exist.
			Expect(c.Get(ctx, client.ObjectKey{Name: cm.Name, Namespace: cm.Namespace}, cm)).To(HaveOccurred())
		})
	})

	Context("liveness and readiness probes", func() {
		It("updates liveness and readiness probe default values", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-deployment-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-daemonset",
							Namespace: "test-namespace",
						},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-daemonset-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&esv1.Elasticsearch{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-elasticsearch",
							Namespace: "test-namespace",
						},
						Spec: esv1.ElasticsearchSpec{
							NodeSets: []esv1.NodeSet{
								{
									PodTemplate: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											Containers: []corev1.Container{
												{
													Name:           "test-elasticsearch-container",
													LivenessProbe:  &corev1.Probe{},
													ReadinessProbe: &corev1.Probe{},
												},
											},
										},
									},
								},
							},
						},
					},
					&kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-kibana",
							Namespace: "test-namespace",
						},
						Spec: kbv1.KibanaSpec{
							PodTemplate: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-kibana-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&monitoringv1.Prometheus{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-prometheus",
							Namespace: "test-namespace",
						},
						Spec: monitoringv1.PrometheusSpec{
							CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
								Containers: []corev1.Container{
									{
										Name:           "test-prometheus-container",
										LivenessProbe:  &corev1.Probe{},
										ReadinessProbe: &corev1.Probe{},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probe default values are set")
			var containers []corev1.Container

			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, deploy.Spec.Template.Spec.Containers...)

			var ds apps.DaemonSet
			err = c.Get(ctx, client.ObjectKey{Name: "test-daemonset", Namespace: "test-namespace"}, &ds)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, ds.Spec.Template.Spec.Containers...)

			var es esv1.Elasticsearch
			err = c.Get(ctx, client.ObjectKey{Name: "test-elasticsearch", Namespace: "test-namespace"}, &es)
			Expect(err).NotTo(HaveOccurred())
			for _, nodeset := range es.Spec.NodeSets {
				containers = append(containers, nodeset.PodTemplate.Spec.Containers...)
			}

			var kb kbv1.Kibana
			err = c.Get(ctx, client.ObjectKey{Name: "test-kibana", Namespace: "test-namespace"}, &kb)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, kb.Spec.PodTemplate.Spec.Containers...)

			var prom monitoringv1.Prometheus
			err = c.Get(ctx, client.ObjectKey{Name: "test-prometheus", Namespace: "test-namespace"}, &prom)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, prom.Spec.Containers...)

			Expect(containers).To(HaveLen(5))
			for _, c := range containers {
				Expect(c.LivenessProbe.FailureThreshold).To(BeEquivalentTo(3))
				Expect(c.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))
				Expect(c.LivenessProbe.SuccessThreshold).To(BeEquivalentTo(1))
				Expect(c.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(5))

				Expect(c.ReadinessProbe.FailureThreshold).To(BeEquivalentTo(3))
				Expect(c.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(30))
				Expect(c.ReadinessProbe.SuccessThreshold).To(BeEquivalentTo(1))
				Expect(c.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(5))
			}
		})

		It("should not modify liveness and readiness probes when values are set", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-deployment-container",
											LivenessProbe: &corev1.Probe{
												FailureThreshold: 2,
												PeriodSeconds:    3,
												SuccessThreshold: 5,
												TimeoutSeconds:   7,
											},
											ReadinessProbe: &corev1.Probe{
												FailureThreshold: 11,
												PeriodSeconds:    13,
												SuccessThreshold: 17,
												TimeoutSeconds:   19,
											},
										},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probe values are not changed")
			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers := deploy.Spec.Template.Spec.Containers

			Expect(containers).To(HaveLen(1))
			Expect(containers[0].LivenessProbe.FailureThreshold).To(BeEquivalentTo(2))
			Expect(containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(3))
			Expect(containers[0].LivenessProbe.SuccessThreshold).To(BeEquivalentTo(5))
			Expect(containers[0].LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(7))
			Expect(containers[0].ReadinessProbe.FailureThreshold).To(BeEquivalentTo(11))
			Expect(containers[0].ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(13))
			Expect(containers[0].ReadinessProbe.SuccessThreshold).To(BeEquivalentTo(17))
			Expect(containers[0].ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(19))
		})

		It("should not modify liveness and readiness probes when nil", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-deployment-container",
										},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probes are still nil")
			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers := deploy.Spec.Template.Spec.Containers

			Expect(containers).To(HaveLen(1))
			Expect(containers[0].LivenessProbe).To(BeNil())
			Expect(containers[0].ReadinessProbe).To(BeNil())
		})
	})

	Context("common labels and labelselector", func() {
		It("updates daemonsets", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-daemonset",
						Namespace: "test-namespace",
					},
					Spec: apps.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			By("checking that the daemonset is created and labels are added")
			expectedLabels := map[string]string{
				"k8s-app":                      "test-daemonset",
				"app.kubernetes.io/name":       "test-daemonset",
				"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
				"app.kubernetes.io/instance":   "default",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/part-of":    "Calico",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "test-daemonset"},
			}
			key := client.ObjectKey{
				Name:      "test-daemonset",
				Namespace: "test-namespace",
			}
			ds := &apps.DaemonSet{}
			Expect(c.Get(ctx, key, ds)).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*ds.Spec.Selector).To(Equal(expectedSelector))
		})
		It("does not change LabelSelector on daemonsets", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-daemonset",
						Namespace: "test-namespace",
					},
					Spec: apps.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"preset-key": "preset-value",
							},
						},
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                      "test-daemonset",
				"app.kubernetes.io/name":       "test-daemonset",
				"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
				"app.kubernetes.io/instance":   "default",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/part-of":    "Calico",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"preset-key": "preset-value"},
			}
			key := client.ObjectKey{
				Name:      "test-daemonset",
				Namespace: "test-namespace",
			}
			ds := &apps.DaemonSet{}
			Expect(c.Get(ctx, key, ds)).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*ds.Spec.Selector).To(Equal(expectedSelector))
		})
		It("updates deployments", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                      "test-deployment",
				"app.kubernetes.io/name":       "test-deployment",
				"app.kubernetes.io/instance":   "default",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/part-of":    "Calico",
				"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "test-deployment"},
			}
			key := client.ObjectKey{
				Name:      "test-deployment",
				Namespace: "test-namespace",
			}
			d := &apps.Deployment{}
			Expect(c.Get(ctx, key, d)).NotTo(HaveOccurred())
			Expect(d.GetLabels()).To(Equal(expectedLabels))
			Expect(d.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*d.Spec.Selector).To(Equal(expectedSelector))
		})
		It("does not change LabelSelector on deployments", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"preset-key": "preset-value",
							},
						},
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                      "test-deployment",
				"app.kubernetes.io/name":       "test-deployment",
				"app.kubernetes.io/component":  "APIServer.operator.tigera.io",
				"app.kubernetes.io/instance":   "default",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/part-of":    "Calico",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"preset-key": "preset-value"},
			}
			key := client.ObjectKey{
				Name:      "test-deployment",
				Namespace: "test-namespace",
			}
			d := &apps.Deployment{}
			Expect(c.Get(ctx, key, d)).To(BeNil())
			Expect(d.GetLabels()).To(Equal(expectedLabels))
			Expect(d.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*d.Spec.Selector).To(Equal(expectedSelector))
		})
		It("adds the host-networked label to a hostNetwork Deployment pod template", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{HostNetwork: true},
						},
					},
				}},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

			d := &apps.Deployment{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, d)).NotTo(HaveOccurred())
			Expect(d.Spec.Template.GetLabels()).To(HaveKeyWithValue(common.HostNetworkedPodLabel, "true"))
		})
		It("does not add the host-networked label to a pod-networked Deployment", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

			d := &apps.Deployment{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, d)).NotTo(HaveOccurred())
			Expect(d.Spec.Template.GetLabels()).NotTo(HaveKey(common.HostNetworkedPodLabel))
		})
		It("adds the host-networked label to a hostNetwork DaemonSet pod template", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-daemonset",
						Namespace: "test-namespace",
					},
					Spec: apps.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{HostNetwork: true},
						},
					},
				}},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

			ds := &apps.DaemonSet{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "test-daemonset", Namespace: "test-namespace"}, ds)).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.GetLabels()).To(HaveKeyWithValue(common.HostNetworkedPodLabel, "true"))
		})
		It("preserves existing pod template labels alongside the host-networked label", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{"existing": "value"},
							},
							Spec: corev1.PodSpec{HostNetwork: true},
						},
					},
				}},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).To(BeNil())

			d := &apps.Deployment{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, d)).NotTo(HaveOccurred())
			Expect(d.Spec.Template.GetLabels()).To(HaveKeyWithValue("existing", "value"))
			Expect(d.Spec.Template.GetLabels()).To(HaveKeyWithValue(common.HostNetworkedPodLabel, "true"))
		})
		DescribeTable("should sanitize common labels so that they pass regexp validation", func(in string) {
			Expect(sanitizeLabel(in)).To(MatchRegexp(`(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?`))
		},
			Entry("Valid, should remain unchanged", "My-Test_String.123"),
			Entry("Invalid start/end, should be trimmed", "__My-Test_String.123.."),
			Entry("Invalid characters (spaces)", "String with spaces"),
			Entry("Invalid characters", "special-chars!@#$%^&*"),
			Entry("Invalid start/end", "-leading-and-trailing-"),
			Entry("Invalid start/end (multiple)", "____-leading-and-trailing-____"),
			Entry("Empty string, should remain empty", ""),
			Entry("Invalid, should become empty", "."),
			Entry("Valid single character", "a"),
			Entry("Valid", "a-b_c.d"),
			Entry("Valid", "1.2.3.4"))
	})
	Context("services account updates should not result in removal of data", func() {
		It("preserves secrets and image pull secrets that were present before object updates", func() {
			sa := &corev1.ServiceAccount{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "a",
					Namespace: "a",
				},
				Secrets:                      []corev1.ObjectReference{{Name: "a"}},
				ImagePullSecrets:             []corev1.LocalObjectReference{{Name: "a"}},
				AutomountServiceAccountToken: nil,
			}
			Expect(c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, sa)).NotTo(HaveOccurred())

			sa.Secrets = nil
			sa.ImagePullSecrets = nil
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs:            []client.Object{sa},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).NotTo(HaveOccurred())
			Expect(c.Get(ctx, client.ObjectKey{Name: "a", Namespace: "a"}, sa)).NotTo(HaveOccurred())
			Expect(sa.Secrets).To(HaveLen(1))
			Expect(sa.ImagePullSecrets).To(HaveLen(1))
		})
	})
	Context("volumes and volume mounts", func() {
		It("orders by name alphabetically", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-deployment-container",
											VolumeMounts: []corev1.VolumeMount{
												{Name: "z"},
												{Name: "y"},
												{Name: "x"},
											},
										},
									},
									Volumes: []corev1.Volume{
										{Name: "c"},
										{Name: "b"},
										{Name: "a"},
									},
								},
							},
						},
					},
					&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-daemonset",
							Namespace: "test-namespace",
						},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-daemonset-container",
											VolumeMounts: []corev1.VolumeMount{
												{Name: "z"},
												{Name: "y"},
												{Name: "x"},
											},
										},
									},
									Volumes: []corev1.Volume{
										{Name: "c"},
										{Name: "b"},
										{Name: "a"},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			Expect(deploy.Spec.Template.Spec.Volumes).To(ConsistOf(
				corev1.Volume{Name: "a"},
				corev1.Volume{Name: "b"},
				corev1.Volume{Name: "c"},
			))
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(
				corev1.VolumeMount{Name: "x"},
				corev1.VolumeMount{Name: "y"},
				corev1.VolumeMount{Name: "z"},
			))

			var ds apps.DaemonSet
			err = c.Get(ctx, client.ObjectKey{Name: "test-daemonset", Namespace: "test-namespace"}, &ds)
			Expect(err).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(
				corev1.Volume{Name: "a"},
				corev1.Volume{Name: "b"},
				corev1.Volume{Name: "c"},
			))
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(
				corev1.VolumeMount{Name: "x"},
				corev1.VolumeMount{Name: "y"},
				corev1.VolumeMount{Name: "z"},
			))
		})
	})

	Context("unsupported ignore annotation", func() {
		It("should return errObjectIgnored from createOrUpdateObject when object has ignore annotation", func() {
			ds := &apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ignored-ds",
					Namespace: "default",
					Annotations: map[string]string{
						"unsupported.operator.tigera.io/ignore": "true",
					},
				},
				Spec: apps.DaemonSetSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test"}},
						Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img"}}},
					},
				},
			}
			Expect(c.Create(ctx, ds)).NotTo(HaveOccurred())

			rendered := ds.DeepCopy()
			rendered.Annotations = nil
			rendered.SetGroupVersionKind(apps.SchemeGroupVersion.WithKind("DaemonSet"))
			err := handler.(*componentHandler).createOrUpdateObject(ctx, rendered, rmeta.OSTypeLinux, nil)
			Expect(stderrors.Is(err, errObjectIgnored)).To(BeTrue())
		})

		It("should not return an error from CreateOrUpdateOrDelete when object has ignore annotation", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ignored-cm",
					Namespace: "default",
					Annotations: map[string]string{
						"unsupported.operator.tigera.io/ignore": "true",
					},
				},
			}
			Expect(c.Create(ctx, cm)).NotTo(HaveOccurred())

			rendered := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ignored-cm",
					Namespace: "default",
				},
				Data: map[string]string{"key": "value"},
			}
			fc := &fakeComponent{
				objs:            []client.Object{rendered},
				supportedOSType: rmeta.OSTypeLinux,
			}
			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("Mocked client Component handler tests", func() {
	var (
		c       client.Client
		mc      mockClient
		ctx     context.Context
		handler ComponentHandler
	)

	BeforeEach(func() {
		mc = mockClient{Info: make([]mockReturn, 0)}
		c = &mc
		ctx = context.Background()

		handler = NewComponentHandler(logf.Log, c, runtime.NewScheme(), nil)

		// Use a new cache for each test.
		dCache = newCache()
	})

	Context("Resource conflicts", func() {
		ds := apps.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ds",
				Namespace: "default",
			},
			Spec: apps.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							fakeComponentAnnotationKey: fakeComponentAnnotationValue,
						},
					},
				},
			},
		}
		setToDS := func(object client.Object) {
			if dsToSet, ok := object.(*apps.DaemonSet); ok {
				ds.DeepCopyInto(dsToSet)
			}
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{&ds},
		}

		It("if Updating a resource conflicts try the update again (retry OK))", func() {
			// One Get call loads the InstallationSpec up-front. The conflict retry re-runs
			// the object update but reuses the already-loaded spec.
			mc.Info = append(mc.Info, mockReturn{Method: "Get", Return: nil})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message")),
			})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToDS,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())

			Expect(mc.Index).To(Equal(5))
		})

		It("if Updating a resource conflicts try the update again (retry fails)", func() {
			// One Get call loads the InstallationSpec up-front. The conflict retry re-runs
			// the object update but reuses the already-loaded spec.
			mc.Info = append(mc.Info, mockReturn{Method: "Get", Return: nil})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message")),
			})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message 2")),
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(mc.Index).To(Equal(5))
			Expect(err).NotTo(BeNil())
		})
	})

	Context("Network Policy updates", func() {
		baseNP := &v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NetworkPolicy",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-system.test-policy",
				Namespace: "tigera-namespace",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "calico-system",
				Selector: "k8s-app == 'tigera-component'",
				Egress: []v3.Rule{
					{
						Action: "Allow",
					},
				},
				Types: []v3.PolicyType{"Egress"},
			},
		}
		setToBaseNP := func(object client.Object) {
			if npToSet, ok := object.(*v3.NetworkPolicy); ok {
				baseNP.DeepCopyInto(npToSet)
			}
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{baseNP},
		}

		// One Get call is issued up-front to load the InstallationSpec.
		installationGets := func() {
			mc.Info = append(mc.Info, mockReturn{Method: "Get", Return: nil})
		}

		It("NetworkPolicy updates are omitted if there is no change", func() {
			installationGets()
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToBaseNP,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(2))
		})

		It("NetworkPolicy updates are applied if there is a change", func() {
			modifiedNP := baseNP.DeepCopy()
			modifiedNP.Spec.Selector = "k8s-app == 'invalid-component'"
			setToModifiedNP := func(object client.Object) {
				if npToSet, ok := object.(*v3.NetworkPolicy); ok {
					modifiedNP.DeepCopyInto(npToSet)
				}
			}

			installationGets()
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToModifiedNP,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToBaseNP,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(3))
		})
	})

	Context("Tier updates", func() {
		order := 9000.0
		baseTier := &v3.Tier{
			TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: "test-tier"},
			Spec:       v3.TierSpec{Order: &order},
		}
		setToBaseTier := func(object client.Object) {
			if tierToSet, ok := object.(*v3.Tier); ok {
				baseTier.DeepCopyInto(tierToSet)
			}
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{baseTier},
		}

		// One Get call is issued up-front to load the InstallationSpec.
		installationGets := func() {
			mc.Info = append(mc.Info, mockReturn{Method: "Get", Return: nil})
		}

		It("Tier updates are omitted if there is no change", func() {
			installationGets()
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToBaseTier,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(2))
		})

		It("Tier updates are applied if there is a change", func() {
			over9000 := 9001.0
			modifiedTier := baseTier.DeepCopy()
			modifiedTier.Spec.Order = &over9000
			setToModifiedTier := func(object client.Object) {
				if tierToSet, ok := object.(*v3.Tier); ok {
					modifiedTier.DeepCopyInto(tierToSet)
				}
			}

			installationGets()
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToModifiedTier,
			})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToBaseTier,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(3))
		})
	})
})

// A fake component that only returns ready and always creates the "test-namespace" Namespace.
type fakeComponent struct {
	objs            []client.Object
	supportedOSType rmeta.OSType
}

func (c *fakeComponent) Ready() bool {
	return true
}

func (c *fakeComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *fakeComponent) Objects() ([]client.Object, []client.Object) {
	return c.objs, nil
}

func (c *fakeComponent) SupportedOSType() rmeta.OSType {
	return c.supportedOSType
}

type mockReturn struct {
	Method       string
	Return       interface{}
	InputMutator func(object client.Object)
}

type mockClient struct {
	Info  []mockReturn
	Index int
}

func (mc *mockClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	panic("not implemented")
}

func (mc *mockClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	panic("not implemented")
}

func (mc *mockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	defer func() { mc.Index++ }()
	funcName := "Get"
	if len(mc.Info) <= mc.Index {
		panic(fmt.Sprintf("mockClient Info doesn't have enough entries for %s %v", funcName, key))
	}
	if mc.Info[mc.Index].Method != funcName {
		panic(fmt.Sprintf("mockClient current (%d) call is for %v, not %s", mc.Index, mc.Info[mc.Index].Method, funcName))
	}
	if mc.Info[mc.Index].Return == nil {
		if mc.Info[mc.Index].InputMutator != nil {
			mc.Info[mc.Index].InputMutator(obj)
		}
		return nil
	}

	v, ok := mc.Info[mc.Index].Return.(error)
	if !ok {
		panic(fmt.Sprintf("mockClient Info didn't have right type for entry %d for %s %v", mc.Index, funcName, key))
	}

	return v
}

func (mc *mockClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	panic("List not implemented in mockClient")
}

func (mc *mockClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	panic("Apply not implemented in mockClient")
}

func (mc *mockClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	panic("Create not implemented in mockClient")
}

func (mc *mockClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	panic("Delete not implemented in mockClient")
}

func (mc *mockClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	defer func() { mc.Index++ }()
	funcName := "Update"
	if len(mc.Info) <= mc.Index {
		panic(fmt.Sprintf("mockClient Info doesn't have enough entries for %s %v", funcName, client.ObjectKeyFromObject(obj)))
	}
	if mc.Info[mc.Index].Method != funcName {
		panic(fmt.Sprintf("mockClient current (%d) call is for %v, not %s", mc.Index, mc.Info[mc.Index].Method, funcName))
	}
	if mc.Info[mc.Index].Return == nil {
		if mc.Info[mc.Index].InputMutator != nil {
			mc.Info[mc.Index].InputMutator(obj)
		}
		return nil
	}

	v, ok := mc.Info[mc.Index].Return.(error)
	if !ok {
		panic(fmt.Sprintf("mockClient Info didn't have right type for entry %d for %s %v", mc.Index, funcName, client.ObjectKeyFromObject(obj)))
	}
	return v
}

func (mc *mockClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	panic("Patch not implemented in mockClient")
}

func (mc *mockClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	panic("DeleteAll not implemented in mockClient")
}

func (mc *mockClient) Status() client.StatusWriter {
	panic("Status not implemented in mockClient")
}

func (mc *mockClient) Scheme() *runtime.Scheme {
	panic("Scheme not implemented in mockClient")
}

func (mc *mockClient) RESTMapper() restMeta.RESTMapper {
	panic("RESTMapper not implemented in mockClient")
}

func (mc *mockClient) SubResource(subResource string) client.SubResourceClient {
	panic("SubResource not implemented in mockClient")
}
