// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egressgateway

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	ocsv1 "github.com/openshift/api/security/v1"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/test"
)

var _ = Describe("Egress Gateway controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileEgressGateway
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var installation *operatorv1.Installation

	Context("EGW reconciliation", func() {
		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			// Create a client that will have a crud interface of k8s objects.
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			ctx = context.Background()
			installation = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:            operatorv1.CalicoEnterprise,
					KubernetesProvider: operatorv1.ProviderNone,
					Registry:           "some.registry.org/",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.CalicoEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
					},
					CalicoVersion: components.EnterpriseRelease,
				},
			}
			mockStatus = &status.MockStatus{}
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
			mockStatus.On("OnCRFound").Return()

			r = ReconcileEgressGateway{
				client:          c,
				scheme:          scheme,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
			}

			Expect(c.Create(ctx, &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool-1"}, Spec: v3.IPPoolSpec{
					CIDR:             "1.2.3.0/24",
					VXLANMode:        v3.VXLANModeAlways,
					IPIPMode:         v3.IPIPModeNever,
					NATOutgoing:      true,
					Disabled:         false,
					DisableBGPExport: true,
					AWSSubnetID:      "aws-subnet-1",
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool-2"}, Spec: v3.IPPoolSpec{
					CIDR:             "1.2.4.0/24",
					VXLANMode:        v3.VXLANModeAlways,
					IPIPMode:         v3.IPIPModeNever,
					NATOutgoing:      true,
					Disabled:         false,
					DisableBGPExport: true,
					AWSSubnetID:      "aws-subnet-2",
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool-4"}, Spec: v3.IPPoolSpec{
					CIDR:             "1.2.5.0/24",
					VXLANMode:        v3.VXLANModeAlways,
					IPIPMode:         v3.IPIPModeNever,
					NATOutgoing:      true,
					Disabled:         false,
					DisableBGPExport: true,
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			})).NotTo(HaveOccurred())

			var routeTableIndex uint32 = 1
			Expect(c.Create(ctx, &v3.ExternalNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "one"}, Spec: v3.ExternalNetworkSpec{
					RouteTableIndex: &routeTableIndex,
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &v3.ExternalNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "two"}, Spec: v3.ExternalNetworkSpec{
					RouteTableIndex: &routeTableIndex,
				},
			})).NotTo(HaveOccurred())
			// Mark that the watch for license key was successful.
			r.licenseAPIReady.MarkAsReady()
		})

		It("should render accurate resources for egress gateway", func() {
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRNotFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("ReadyToMonitor")
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

			By("applying the Egress Gateway CR with just the required fields to the fake cluster")
			var replicas int32 = 2
			logSeverity := operatorv1.LogSeverityInfo
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas:    &replicas,
					LogSeverity: &logSeverity,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1", CIDR: ""},
						{Name: "", CIDR: "1.2.4.0/24"},
					},
					ExternalNetworks: []string{"one", "two"},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.status.IsAvailable()).To(BeTrue())

			dep := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-red",
					Namespace: "calico-egress",
				},
			}
			By("ensuring the egw resources created properly with default values")
			Expect(test.GetResource(c, &dep)).To(BeNil())
			Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(dep.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer := dep.Spec.Template.Spec.InitContainers[0]
			Expect(initContainer.Image).To(Equal(fmt.Sprintf("some.registry.org/%s%s:%s",
				components.TigeraImagePath,
				components.ComponentEgressGateway.Image, components.ComponentEgressGateway.Version)))
			egwContainer := dep.Spec.Template.Spec.Containers[0]
			Expect(egwContainer.Image).To(Equal(fmt.Sprintf("some.registry.org/%s%s:%s",
				components.TigeraImagePath,
				components.ComponentEgressGateway.Image, components.ComponentEgressGateway.Version)))
			Expect(dep.Spec.Template.ObjectMeta.Labels["projectcalico.org/egw"]).To(Equal(dep.Name))
			expectedInitEnvVar := []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4790"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
			}
			expectedEgwEnvVar := []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "HEALTH_PORT", Value: "8080"},
				{Name: "LOG_SEVERITY", Value: "Info"},
			}
			for _, elem := range expectedEgwEnvVar {
				Expect(egwContainer.Env).To(ContainElement(elem))
			}
			expectedAffinity := corev1.Affinity{}
			expectedAffinity.PodAntiAffinity = &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
					{
						Weight: 1,
						PodAffinityTerm: corev1.PodAffinityTerm{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"projectcalico.org/egw": "calico-red"},
							},
							TopologyKey: "topology.kubernetes.io/zone",
						},
					},
				},
			}
			Expect(*dep.Spec.Template.Spec.Affinity).To(Equal(expectedAffinity))
			Expect(dep.Spec.Template.ObjectMeta.Annotations["cni.projectcalico.org/ipv4pools"]).To(Equal("[\"ippool-1\",\"1.2.4.0/24\"]"))
			Expect(dep.Spec.Template.ObjectMeta.Annotations["egress.projectcalico.org/externalNetworkNames"]).To(Equal("[\"one\",\"two\"]"))

			By("update egw with empty metadata")
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			egw.Spec.Template = &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{}}
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			Expect(dep.Spec.Template.ObjectMeta.Labels["projectcalico.org/egw"]).To(Equal(dep.Name))

			By("update egw with log level")
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			logSeverity = operatorv1.LogSeverityDebug
			egw.Spec.LogSeverity = &logSeverity
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			egwContainer = dep.Spec.Template.Spec.Containers[0]
			expectedEgwEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "HEALTH_PORT", Value: "8080"},
				{Name: "LOG_SEVERITY", Value: "Debug"},
			}
			for _, elem := range expectedEgwEnvVar {
				Expect(egwContainer.Env).To(ContainElement(elem))
			}
			fc := &v3.FelixConfiguration{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "default", Namespace: ""}, fc)).NotTo(HaveOccurred())
			Expect(fc.Spec.PolicySyncPathPrefix).To(Equal("/var/run/nodeagent"))

			By("setting AWS elastic IPs")
			nativeIP := operatorv1.NativeIPEnabled
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			egw.Spec.AWS = &operatorv1.AWSEgressGateway{ElasticIPs: []string{"4.5.6.7"}, NativeIP: &nativeIP}
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("updating felix config")
			egw_blue := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-blue", Namespace: "calico-gw"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas:    &replicas,
					LogSeverity: &logSeverity,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
						{Name: "ippool-2"},
					},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw_blue)).NotTo(HaveOccurred())

			Expect(c.Get(ctx, types.NamespacedName{Name: "default", Namespace: ""}, fc)).NotTo(HaveOccurred())
			vxlanPort := 4800
			vxlanVni := 4100
			fc.Spec.EgressIPVXLANPort = &vxlanPort
			fc.Spec.EgressIPVXLANVNI = &vxlanVni
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			dep_blue := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-blue",
					Namespace: "calico-gw",
				},
			}
			Expect(test.GetResource(c, &dep_blue)).To(BeNil())
			initContainer = dep.Spec.Template.Spec.InitContainers[0]
			initContainer_blue := dep_blue.Spec.Template.Spec.InitContainers[0]
			expectedInitEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4100"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4800"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
				Expect(initContainer_blue.Env).To(ContainElement(elem))
			}
			var backend v3.IptablesBackend
			backend = "Auto"
			fc.Spec.IptablesBackend = &backend
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			dep_blue = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-blue",
					Namespace: "calico-gw",
				},
			}
			Expect(test.GetResource(c, &dep_blue)).To(BeNil())
			initContainer = dep.Spec.Template.Spec.InitContainers[0]
			initContainer_blue = dep_blue.Spec.Template.Spec.InitContainers[0]
			expectedInitEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4100"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4800"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
				Expect(initContainer_blue.Env).To(ContainElement(elem))
			}

			backend = "legacy"
			fc.Spec.IptablesBackend = &backend
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			dep_blue = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-blue",
					Namespace: "calico-gw",
				},
			}
			Expect(test.GetResource(c, &dep_blue)).To(BeNil())
			initContainer = dep.Spec.Template.Spec.InitContainers[0]
			initContainer_blue = dep_blue.Spec.Template.Spec.InitContainers[0]
			expectedInitEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4100"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4800"},
				{Name: "IPTABLES_BACKEND", Value: "legacy"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
				Expect(initContainer_blue.Env).To(ContainElement(elem))
			}

			backend = "NFT"
			fc.Spec.IptablesBackend = &backend
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			dep_blue = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-blue",
					Namespace: "calico-gw",
				},
			}
			Expect(test.GetResource(c, &dep_blue)).To(BeNil())
			initContainer = dep.Spec.Template.Spec.InitContainers[0]
			initContainer_blue = dep_blue.Spec.Template.Spec.InitContainers[0]
			expectedInitEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4100"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4800"},
				{Name: "IPTABLES_BACKEND", Value: "nft"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
				Expect(initContainer_blue.Env).To(ContainElement(elem))
			}
		})

		It("should use a single scc when EGW is created in openshift", func() {
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("RemoveDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRNotFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("ReadyToMonitor")
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

			r.provider = operatorv1.ProviderOpenShift
			logSeverity := operatorv1.LogSeverityInfo
			egw_red := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					LogSeverity: &logSeverity,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1", CIDR: ""},
						{Name: "", CIDR: "1.2.4.0/24"},
					},
					ExternalNetworks: []string{"one", "two"},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}

			egw_blue := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-blue", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					LogSeverity: &logSeverity,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1", CIDR: ""},
						{Name: "", CIDR: "1.2.4.0/24"},
					},
					ExternalNetworks: []string{"one", "two"},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			scc := ocsv1.SecurityContextConstraints{
				TypeMeta: metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-egressgateway",
				},
			}

			Expect(c.Create(ctx, egw_red)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &scc)).To(BeNil())
			Expect(len(scc.Users)).To(Equal(1))
			Expect(scc.Users[0]).To(Equal("system:serviceaccount:calico-egress:calico-red"))

			Expect(c.Create(ctx, egw_blue)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &scc)).To(BeNil())
			Expect(len(scc.Users)).To(Equal(2))
			Expect(scc.Users[0]).To(Equal("system:serviceaccount:calico-egress:calico-blue"))
			Expect(scc.Users[1]).To(Equal("system:serviceaccount:calico-egress:calico-red"))

			Expect(c.Delete(ctx, egw_red)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &scc)).To(BeNil())
			Expect(len(scc.Users)).To(Equal(1))
			Expect(scc.Users[0]).To(Equal("system:serviceaccount:calico-egress:calico-blue"))

			Expect(c.Delete(ctx, egw_blue)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &scc)).NotTo(BeNil())
		})

		It("Should throw an error when ippool is not present", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "ippools.crd.projectcalico.org \"ippool-3\" not found", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-3"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when CIDR does not match any IPPool", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "IPPool matching CIDR = 2.2.3.0/24 not present", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "", CIDR: "2.2.3.0/24"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when ippool name and CIRD do not match", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "IPPool CIDR does not match with name", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-2", CIDR: "1.2.3.0/24"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when elastic IPs are specified and native IP disabled", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "NativeIP must be enabled when elastic IPs are used", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					AWS:      &operatorv1.AWSEgressGateway{ElasticIPs: []string{"5.6.7.8"}},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when failure detection is specified without ICMP and HTTP probes", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "either ICMP or HTTP probe must be configured", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					EgressGatewayFailureDetection: &operatorv1.EgressGatewayFailureDetection{},
					Template:                      &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when native IP is enabled and IPPool CIDR is not backed by aws subnet ID", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "AWS subnet ID must be set when NativeIP is enabled", mock.Anything, mock.Anything)
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			nativeIP := operatorv1.NativeIPEnabled
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "", CIDR: "1.2.5.0/24"},
					},
					AWS:      &operatorv1.AWSEgressGateway{NativeIP: &nativeIP},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when native IP is enabled and IPPool name is not backed by aws subnet ID", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "AWS subnet ID must be set when NativeIP is enabled", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			nativeIP := operatorv1.NativeIPEnabled
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-4", CIDR: ""},
					},
					AWS:      &operatorv1.AWSEgressGateway{NativeIP: &nativeIP},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when ICMP timeout is less than ICMP interval", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "ICMP probe timeout must be greater than interval", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			var timeout int32 = 5
			var interval int32 = 10
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
					EgressGatewayFailureDetection: &operatorv1.EgressGatewayFailureDetection{
						ICMPProbe: &operatorv1.ICMPProbe{
							IPs:             []string{"1.2.4.5"},
							TimeoutSeconds:  &timeout,
							IntervalSeconds: &interval,
						},
					},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when HTTP timeout is less than HTTP interval", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "HTTP probe timeout must be greater than interval", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			var timeout int32 = 5
			var interval int32 = 10
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
					EgressGatewayFailureDetection: &operatorv1.EgressGatewayFailureDetection{
						HTTPProbe: &operatorv1.HTTPProbe{
							URLs:            []string{"test.com"},
							TimeoutSeconds:  &timeout,
							IntervalSeconds: &interval,
						},
					},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("Should throw an error when externalNetworks are not present", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Error validating egress gateway Name = calico-red, Namespace = calico-egress", "externalnetworks.crd.projectcalico.org \"three\" not found", mock.Anything, mock.Anything).Return()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					ExternalNetworks: []string{"one", "three"},
					Template:         &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertExpectations(GinkgoT())
		})

		It("should wait for correct calico version before reconciling EGW", func() {
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRNotFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("ReadyToMonitor")
			installation.Status.CalicoVersion = "3.15"
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

			requeueInterval := 30 * time.Second

			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas:    ptr.To(int32(2)),
					LogSeverity: ptr.To(operatorv1.LogSeverityInfo),
					IPPools: []operatorv1.EgressGatewayIPPool{
						{Name: "ippool-1"},
					},
					Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}

			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(requeueInterval))

			dep := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-red",
					Namespace: "calico-egress",
				},
			}
			By("ensuring the egw resources are created after correct calico version is installed")
			Expect(test.GetResource(c, &dep)).NotTo(BeNil())

			result, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result.RequeueAfter).Should(Equal(requeueInterval))

			ins := &operatorv1.Installation{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, ins)).NotTo(HaveOccurred())
			ins.Status.CalicoVersion = components.EnterpriseRelease
			Expect(c.Status().Update(ctx, ins)).NotTo(HaveOccurred())

			result, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result.RequeueAfter).Should(BeEquivalentTo(0))

			Expect(test.GetResource(c, &dep)).To(BeNil())
		})

		It("should not watch namespaced resources", func() {
			m := &mockController{}
			var mgr manager.Manager
			err := add(mgr, m)
			Expect(err).ShouldNot(HaveOccurred())
			for _, obj := range m.watchedObjects {
				Expect(len(obj.GetNamespace())).To(Equal(0))
			}
		})
	})
})

type mockController struct {
	mock.Mock
	watchedObjects []client.Object
}

func (m *mockController) WatchObject(object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	m.watchedObjects = append(m.watchedObjects, object)
	return nil
}

func (m *mockController) WatchObjectInCache(_ cache.Cache, object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	m.watchedObjects = append(m.watchedObjects, object)
	return nil
}

func (m *mockController) Watch(src source.Source) error {
	panic("not implemented")
}

func (m *mockController) Start(ctx context.Context) error {
	return nil
}

func (m *mockController) GetLogger() logr.Logger {
	var logger logr.Logger
	return logger
}

func (m *mockController) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	return reconcile.Result{}, nil
}
