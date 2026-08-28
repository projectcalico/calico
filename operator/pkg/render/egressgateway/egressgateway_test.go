// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package egressgateway_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/egressgateway"
)

var _ = Describe("Egress Gateway rendering tests", func() {
	var installation *operatorv1.InstallationSpec
	var egw *operatorv1.EgressGateway
	var replicas int32 = 2
	var healthTimeoutDS int32 = 30
	var interval int32 = 20
	var timeout int32 = 40
	var pullSecrets []*corev1.Secret
	rbac := "rbac.authorization.k8s.io"
	logSeverity := operatorv1.LogSeverityInfo
	labels := map[string]string{"egress-code": "red"}

	topoConstraint := corev1.TopologySpreadConstraint{
		MaxSkew:           100,
		TopologyKey:       "topology.kubernetes.io/zone",
		WhenUnsatisfiable: "DoNotSchedule",
		LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
	}

	weightedPodAffinity := corev1.WeightedPodAffinityTerm{
		Weight: 100,
		PodAffinityTerm: corev1.PodAffinityTerm{
			LabelSelector: &metav1.LabelSelector{MatchLabels: labels},
			TopologyKey:   "topology.kuberneted.io/zone",
		},
	}

	affinity := &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{weightedPodAffinity}}}

	priorityClassName := "priority-x"

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}
		egw = &operatorv1.EgressGateway{
			Spec: operatorv1.EgressGatewaySpec{
				Replicas: &replicas,
				IPPools: []operatorv1.EgressGatewayIPPool{
					{Name: "ippool-1", CIDR: ""},
					{Name: "ippool-2", CIDR: ""},
				},
				ExternalNetworks: []string{"one", "two"},
				LogSeverity:      &logSeverity,
				Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{
					Metadata: &operatorv1.EgressGatewayMetadata{Labels: labels},
					Spec: &operatorv1.EgressGatewayDeploymentPodSpec{
						Affinity:     affinity,
						NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
						TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
							topoConstraint,
						},
						PriorityClassName: priorityClassName,
					},
				},
				EgressGatewayFailureDetection: &operatorv1.EgressGatewayFailureDetection{
					HealthTimeoutDataStoreSeconds: &healthTimeoutDS,
					ICMPProbe:                     &operatorv1.ICMPProbe{IPs: []string{"1.2.3.4"}, TimeoutSeconds: &timeout, IntervalSeconds: &interval},
					HTTPProbe:                     &operatorv1.HTTPProbe{URLs: []string{"test.com"}, TimeoutSeconds: &timeout, IntervalSeconds: &interval},
				},
			},
		}
		egw.Name = "egress-test"
		egw.Namespace = "test-ns"

		pullSecrets = []*corev1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			},
		}
	})

	It("should render EGW deployment", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-operator-secrets", "test-ns", "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"test-secret", "test-ns", "", "v1", "Secret"},
			{"egress-test", "test-ns", "", "v1", "ServiceAccount"},
			{"egress-test", "test-ns", "apps", "v1", "Deployment"},
		}

		expectedResToBeDeleted := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"egress-test", "test-ns", rbac, "v1", "Role"},
			{"egress-test", "test-ns", rbac, "v1", "RoleBinding"},
		}

		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:     pullSecrets,
			Installation:    installation,
			OSType:          rmeta.OSTypeLinux,
			EgressGW:        egw,
			VXLANVNI:        4097,
			VXLANPort:       4790,
			IptablesBackend: "nft",
		})
		resources, resToBeDeleted := component.Objects()
		Expect(resources).To(HaveLen(len(expectedResources)))
		Expect(resToBeDeleted).To(HaveLen(len(expectedResToBeDeleted)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		for i, expectedResToBeDeleted := range expectedResToBeDeleted {
			rtest.ExpectResourceTypeAndObjectMetadata(resToBeDeleted[i], expectedResToBeDeleted.name, expectedResToBeDeleted.ns, expectedResToBeDeleted.group,
				expectedResToBeDeleted.version, expectedResToBeDeleted.kind)
		}

		dep := rtest.GetResource(resources, "egress-test", "test-ns", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Replicas).NotTo(BeNil())
		Expect(*dep.Spec.Replicas).To(BeNumerically("==", 2))
		Expect(len(dep.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(len(dep.Spec.Template.Spec.InitContainers)).To(Equal(1))
		Expect(len(dep.Spec.Template.Spec.Volumes)).To(Equal(1))
		expectedVolume := corev1.Volume{
			Name: "policysync",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver: "csi.tigera.io",
				},
			},
		}
		Expect(dep.Spec.Template.Spec.Volumes).To(ContainElement(expectedVolume))
		Expect(dep.Spec.Template.Spec.ServiceAccountName).To(Equal("egress-test"))
		initContainer := dep.Spec.Template.Spec.InitContainers[0]
		egwContainer := dep.Spec.Template.Spec.Containers[0]
		egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
		egressPodIps := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIPs"}}
		expectedInitEnvVars := []corev1.EnvVar{
			{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
			{Name: "EGRESS_VXLAN_PORT", Value: "4790"},
			{Name: "IPTABLES_BACKEND", Value: "nft"},
			{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
			{Name: "EGRESS_POD_IPS", ValueFrom: egressPodIps},
		}
		for _, elem := range expectedInitEnvVars {
			Expect(initContainer.Env).To(ContainElement(elem))
		}
		Expect(*initContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*initContainer.SecurityContext.Privileged).To(BeTrue())
		Expect(*initContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*initContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*initContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(initContainer.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(initContainer.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		expectedEnvVars := []corev1.EnvVar{
			{Name: "HEALTH_PORT", Value: "8080"},
			{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
			{Name: "LOG_SEVERITY", Value: "Info"},
			{Name: "HEALTH_TIMEOUT_DATASTORE", Value: "30s"},
			{Name: "ICMP_PROBE_INTERVAL", Value: "20s"},
			{Name: "ICMP_PROBE_TIMEOUT", Value: "40s"},
			{Name: "HTTP_PROBE_INTERVAL", Value: "20s"},
			{Name: "HTTP_PROBE_TIMEOUT", Value: "40s"},
			{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
			{Name: "EGRESS_POD_IPS", ValueFrom: egressPodIps},
		}
		for _, elem := range expectedEnvVars {
			Expect(egwContainer.Env).To(ContainElement(elem))
		}
		ipPoolAnnotation := dep.Spec.Template.Annotations["cni.projectcalico.org/ipv4pools"]
		expectedIPPoolAnnotation := "[\"ippool-1\",\"ippool-2\"]"
		Expect(ipPoolAnnotation).To(Equal(expectedIPPoolAnnotation))
		Expect(dep.Spec.Template.ObjectMeta.Annotations["egress.projectcalico.org/externalNetworkNames"]).To(Equal("[\"one\",\"two\"]"))

		Expect(dep.Spec.Template.ObjectMeta.Labels).To(Equal(labels))
		expectedPort := corev1.ContainerPort{
			ContainerPort: egressgateway.DefaultHealthPort,
			Name:          "health",
			Protocol:      corev1.ProtocolTCP,
		}
		Expect(egwContainer.Ports).To(ContainElement(expectedPort))
		Expect(dep.Spec.Template.Spec.NodeSelector["kubernetes.io/os"]).To(Equal("linux"))
		Expect(*egwContainer.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*egwContainer.SecurityContext.Privileged).To(BeFalse())
		Expect(*egwContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*egwContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*egwContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(egwContainer.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW"},
			},
		))
		Expect(egwContainer.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		expectedRP := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/readiness",
					Port: intstr.FromInt(int(egressgateway.DefaultHealthPort)),
				},
			},
			InitialDelaySeconds: 10,
		}
		Expect(egwContainer.ReadinessProbe).To(Equal(expectedRP))

		volumeMount := corev1.VolumeMount{Name: "policysync", MountPath: "/var/run/calico"}
		Expect(egwContainer.VolumeMounts).To(ContainElement(volumeMount))

		Expect(dep.Spec.Template.Spec.TopologySpreadConstraints).To(ContainElement(topoConstraint))
		Expect(dep.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(dep.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
	})

	It("should have proper annotations and resources if aws is set", func() {
		recommendedQuantity := resource.NewQuantity(1, resource.DecimalSI)
		expectedResource := corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity, "cpu": resource.MustParse("100m")},
			Requests: corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity, "cpu": resource.MustParse("100m")},
		}

		nativeIP := operatorv1.NativeIPEnabled
		egw.Spec.AWS = &operatorv1.AWSEgressGateway{NativeIP: &nativeIP, ElasticIPs: []string{"1.2.3.4", "5.6.7.8"}}
		deploymentContainer := operatorv1.EGWDeploymentContainer{
			Name: "egress-gateway",
			Resources: &corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{"cpu": resource.MustParse("100m")},
				Requests: corev1.ResourceList{"cpu": resource.MustParse("100m")},
			},
		}
		egw.Spec.Template.Spec.Containers = append(egw.Spec.Template.Spec.Containers, deploymentContainer)
		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:  nil,
			Installation: installation,
			OSType:       rmeta.OSTypeLinux,
			EgressGW:     egw,
			VXLANVNI:     4097,
			VXLANPort:    4790,
		})
		resources, _ := component.Objects()
		Expect(resources).To(HaveLen(3))
		dep := rtest.GetResource(resources, "egress-test", "test-ns", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Resources).To(Equal(expectedResource))
		elasticIPAnnotation := dep.Spec.Template.Annotations["cni.projectcalico.org/awsElasticIPs"]
		Expect(elasticIPAnnotation).To(Equal("[\"1.2.3.4\",\"5.6.7.8\"]"))
	})

	It("should create SecurityContextConstraints if platform is OpenShift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-operator-secrets", "test-ns", "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"egress-test", "test-ns", "", "v1", "ServiceAccount"},
			{"egress-test", "test-ns", rbac, "v1", "Role"},
			{"egress-test", "test-ns", rbac, "v1", "RoleBinding"},
			{"tigera-egressgateway", "", "security.openshift.io", "v1", "SecurityContextConstraints"},
			{"egress-test", "test-ns", "apps", "v1", "Deployment"},
		}

		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:  nil,
			Installation: installation,
			OSType:       rmeta.OSTypeLinux,
			EgressGW:     egw,
			VXLANVNI:     4097,
			VXLANPort:    4790,
			OpenShift:    true,
		})
		resources, _ := component.Objects()
		Expect(resources).To(HaveLen(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render toleration on GKE", func() {
		installation.KubernetesProvider = operatorv1.ProviderGKE

		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:  nil,
			Installation: installation,
			OSType:       rmeta.OSTypeLinux,
			EgressGW:     egw,
			VXLANVNI:     4097,
			VXLANPort:    4790,
			OpenShift:    true,
		})
		resources, _ := component.Objects()
		deploy := rtest.GetResource(resources, "egress-test", "test-ns", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deploy).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})
})
