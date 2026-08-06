// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whisker_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	defaultWhiskerKeyPair    = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: whisker.WhiskerKeyPairSecret}}, nil, "")
	defaultTLSKeyPair        = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-pair"}}, nil, "")
	defaultTrustedCertBundle = certificatemanagement.CreateTrustedBundle(nil)
	numExpectedObjects       = 5
	numDeprecatedObjects     = 1

	// calicoImageRef resolves the combined calico/calico image exactly as the
	// renderer does, so the expected image tracks the pinned ComponentCalico
	// version on any branch (:master on master, :v3.32.x on release-v1.43)
	// rather than a hardcoded tag.
	calicoImageRef, _ = components.GetReference(components.CombinedCalicoImage(&operatorv1.InstallationSpec{Variant: operatorv1.Calico}), "", "", "", nil)
	// whiskerImageRef resolves the whisker image the same way the renderer does.
	whiskerImageRef, _ = components.GetReference(components.ComponentCalicoWhisker, "", "", "", nil)
)

var _ = Describe("ComponentRendering", func() {
	DescribeTable("Creation and deletion counts", func(cfg *whisker.Configuration, createObjs, delObjs int) {
		component := whisker.Whisker(cfg)
		objsToCreate, objsToDelete := component.Objects()
		Expect(objsToCreate).To(HaveLen(createObjs))
		Expect(objsToDelete).To(HaveLen(delObjs))
	},
		Entry("Should return objects to create when variant is Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerKeyPair:        defaultWhiskerKeyPair,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			},
			numExpectedObjects, numDeprecatedObjects,
		),
		Entry("Should return objects to delete when variant is not Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.CalicoEnterprise,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerKeyPair:        defaultWhiskerKeyPair,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			},
			0, numExpectedObjects+numDeprecatedObjects,
		),
	)

	DescribeTable("Whisker Deployment", func(cfg *whisker.Configuration, expected *appsv1.Deployment) {
		component := whisker.Whisker(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		objsToCreate, _ := component.Objects()

		deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment).To(Equal(expected), cmp.Diff(deployment, expected))
	},
		Entry("Should return objects to create when variant is Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerKeyPair:        defaultWhiskerKeyPair,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
				ClusterID:             "test-cluster-id",
				CalicoVersion:         "test-calico-version",
				ClusterType:           "test-cluster-type",
				ClusterDomain:         "cluster.domain",
			},
			&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      whisker.WhiskerDeploymentName,
					Namespace: whisker.WhiskerNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To(int32(1)),
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RecreateDeploymentStrategyType,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name: whisker.WhiskerDeploymentName,
							Annotations: map[string]string{
								defaultWhiskerKeyPair.HashAnnotationKey(): defaultWhiskerKeyPair.HashAnnotationValue(),
								defaultTLSKeyPair.HashAnnotationKey():     defaultTLSKeyPair.HashAnnotationValue(),
							},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: whisker.WhiskerServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:  whisker.WhiskerContainerName,
									Image: whiskerImageRef,
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "CALICO_VERSION", Value: "test-calico-version"},
										{Name: "CLUSTER_ID", Value: "test-cluster-id"},
										{Name: "CLUSTER_TYPE", Value: "test-cluster-type"},
										{Name: "NOTIFICATIONS", Value: "Enabled"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "nginx-config",
											MountPath: "/etc/nginx/conf.d",
											ReadOnly:  true,
										},
										defaultWhiskerKeyPair.VolumeMount(rmeta.OSTypeLinux),
									},
								},
								{
									Name:    whisker.WhiskerBackendContainerName,
									Image:   calicoImageRef,
									Command: []string{"/usr/bin/calico", "component", "whisker-backend"},
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "3002"},
										{Name: "GOLDMANE_HOST", Value: "goldmane.calico-system.svc.cluster.domain:7443"},
										{Name: "TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "SERVER_TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "SERVER_TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: append(
										defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux),
										defaultTLSKeyPair.VolumeMount(rmeta.OSTypeLinux)),
								},
							},
							Volumes: []corev1.Volume{
								defaultTrustedCertBundle.Volume(),
								defaultWhiskerKeyPair.Volume(),
								defaultTLSKeyPair.Volume(),
								{
									Name: "nginx-config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "whisker-nginx-config"},
										},
									},
								},
							},
						},
					},
				},
			},
		),
	)

	It("should generate an IPv4-only NGINX configuration", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			ClusterID:             "test-cluster-id",
			CalicoVersion:         "test-calico-version",
			ClusterType:           "test-cluster-type",
			ClusterDomain:         "cluster.domain",
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		config, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "whisker-nginx-config", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())

		actual, ok := config.Data["default.conf"]
		Expect(ok).To(BeTrue(), "expected default.conf to be present in config map")
		Expect(actual).To(Equal(whisker.NginxConfigV4))
	})

	It("should generate a dual-stack NGINX configuration", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					NodeAddressAutodetectionV6: &operatorv1.NodeAddressAutodetection{
						FirstFound: ptr.To(true),
					},
				},
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			ClusterID:             "test-cluster-id",
			CalicoVersion:         "test-calico-version",
			ClusterType:           "test-cluster-type",
			ClusterDomain:         "cluster.domain",
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		config, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "whisker-nginx-config", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())

		actual, ok := config.Data["default.conf"]
		Expect(ok).To(BeTrue(), "expected default.conf to be present in config map")
		Expect(actual).To(Equal(whisker.NginxConfigDual))
	})

	It("should render a service with HTTPS port", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		svc, err := rtest.GetResourceOfType[*corev1.Service](objsToCreate, "whisker", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(svc.Spec.Ports).To(HaveLen(1))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(whisker.WhiskerServicePort)))
	})

	It("Should apply overrides", func() {
		affinity := &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "custom-affinity-key",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						},
					},
				},
			},
		}
		whiskerResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}
		whiskerbackendResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
			},
		}
		nodeSelector := map[string]string{
			"some-selector": "an override of a default nodeSelector key",
		}
		podLabels := map[string]string{
			"extra-label": "extra",
		}
		podAnnotations := map[string]string{
			"extra-annotation": "extra",
		}
		tolerations := []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}
		topologyConstraints := []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		}

		priorityClassName := "priority-class"

		overrides := &operatorv1.WhiskerDeployment{
			Spec: &operatorv1.WhiskerDeploymentSpec{
				Template: &operatorv1.WhiskerDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{
						Labels:      podLabels,
						Annotations: podAnnotations,
					},
					Spec: &operatorv1.WhiskerDeploymentPodSpec{
						Affinity: affinity,
						Containers: []operatorv1.WhiskerDeploymentContainer{
							{
								Name:      "whisker",
								Resources: whiskerResources,
							},
							{
								Name:      "whisker-backend",
								Resources: whiskerbackendResources,
							},
						},
						NodeSelector:              nodeSelector,
						TopologySpreadConstraints: topologyConstraints,
						Tolerations:               tolerations,
						PriorityClassName:         priorityClassName,
					},
				},
			},
		}

		deployment, err := GetOverriddenWhiskerDeployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment.Spec.Template.ObjectMeta.Labels).To(Equal(podLabels))
		// Override annotations are merged on top of the rendered key pair hash annotations.
		expectedAnnotations := map[string]string{
			defaultWhiskerKeyPair.HashAnnotationKey(): defaultWhiskerKeyPair.HashAnnotationValue(),
			defaultTLSKeyPair.HashAnnotationKey():     defaultTLSKeyPair.HashAnnotationValue(),
		}
		for k, v := range podAnnotations {
			expectedAnnotations[k] = v
		}
		Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(Equal(expectedAnnotations))
		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(deployment.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
		Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
		Expect(deployment.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
		Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*whiskerResources))
		Expect(deployment.Spec.Template.Spec.Containers[1].Resources).To(Equal(*whiskerbackendResources))
	})
})

func GetOverriddenWhiskerDeployment(overrides *operatorv1.WhiskerDeployment) (*appsv1.Deployment, error) {
	component := whisker.Whisker(&whisker.Configuration{
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
			Variant:            operatorv1.Calico,
		},
		TrustedCertBundle:     defaultTrustedCertBundle,
		WhiskerKeyPair:        defaultWhiskerKeyPair,
		WhiskerBackendKeyPair: defaultTLSKeyPair,
		Whisker: &operatorv1.Whisker{
			Spec: operatorv1.WhiskerSpec{
				WhiskerDeployment: overrides,
				Notifications:     ptr.To(operatorv1.Enabled),
			},
		},
	})

	objsToCreate, _ := component.Objects()
	return rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
}
