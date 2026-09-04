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
	"reflect"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/whisker"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var (
	defaultWhiskerKeyPair    = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: whisker.WhiskerKeyPairSecret}}, nil, "")
	defaultTLSKeyPair        = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-pair"}}, nil, "")
	defaultTrustedCertBundle = certificatemanagement.CreateTrustedBundle(nil)
	numExpectedObjects       = 5
	numDeprecatedObjects     = 1

	// Backend only: ServiceAccount, Deployment and NetworkPolicy. The nginx
	// ConfigMap and UI Service join the deprecated objects for deletion.
	numBackendOnlyObjects        = 3
	numBackendOnlyDeletedObjects = numDeprecatedObjects + 2

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
		Entry("Should return the whisker objects to create",
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
		Entry("Should return only the backend objects when BackendOnly is set",
			backendOnlyConfiguration(),
			numBackendOnlyObjects, numBackendOnlyDeletedObjects,
		),
	)

	Context("backend only", func() {
		It("deploys the backend container alone, with no UI or Goldmane wiring", func() {
			component := whisker.Whisker(backendOnlyConfiguration())
			objsToCreate, objsToDelete := component.Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			backend := deployment.Spec.Template.Spec.Containers[0]
			Expect(backend.Name).To(Equal(whisker.WhiskerBackendContainerName))
			for _, e := range backend.Env {
				Expect(e.Name).NotTo(Equal("GOLDMANE_HOST"))
			}
			Expect(deployment.Spec.Template.Spec.Volumes).To(ConsistOf(
				defaultTrustedCertBundle.Volume(),
				defaultTLSKeyPair.Volume(),
			))
			Expect(deployment.Spec.Template.Annotations).To(Equal(map[string]string{
				defaultTLSKeyPair.HashAnnotationKey(): defaultTLSKeyPair.HashAnnotationValue(),
			}))

			// The UI's ConfigMap and Service are removed rather than left to GC,
			// since the Whisker CR that owns them still exists.
			_, err = rtest.GetResourceOfType[*corev1.ConfigMap](objsToDelete, "whisker-nginx-config", whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = rtest.GetResourceOfType[*corev1.Service](objsToDelete, whisker.WhiskerName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, whisker.WhiskerPolicyName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			for _, rule := range np.Spec.Egress {
				Expect(rule.Destination.Selector).NotTo(Equal(networkpolicy.KubernetesAppSelector(whisker.GoldmaneDeploymentName)),
					"the variant wires the backend to its own flow source")
			}
		})

		It("resolves images from an ImageSet that does not carry the UI image", func() {
			is := &operatorv1.ImageSet{Spec: operatorv1.ImageSetSpec{Images: []operatorv1.Image{
				{Image: "calico/calico", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			}}}

			Expect(whisker.Whisker(backendOnlyConfiguration()).ResolveImages(is)).To(Succeed())

			full := backendOnlyConfiguration()
			full.BackendOnly = false
			full.WhiskerKeyPair = defaultWhiskerKeyPair
			Expect(whisker.Whisker(full).ResolveImages(is)).To(MatchError(ContainSubstring("whisker")),
				"the full deployment still needs the UI image")
		})

		It("wires token verification into the backend when a key validator is configured", func() {
			authn := &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"},
			}}
			validator := render.NewDexKeyValidatorConfig(authn, dns.DefaultClusterDomain)
			cfg := backendOnlyConfiguration()
			cfg.KeyValidatorConfig = validator

			objsToCreate, _ := whisker.Whisker(cfg).Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			backend := deployment.Spec.Template.Spec.Containers[0]
			Expect(validator.RequiredEnv("")).NotTo(BeEmpty())
			for _, e := range validator.RequiredEnv("") {
				Expect(backend.Env).To(ContainElement(e))
			}
			for k, v := range validator.RequiredAnnotations() {
				Expect(deployment.Spec.Template.Annotations).To(HaveKeyWithValue(k, v))
			}

			// The backend fetches the provider's keys over the network. The files a
			// browser-facing server mounts are not rendered, so a ConfigMap another
			// component owns is never fought over.
			Expect(deployment.Spec.Template.Spec.Volumes).To(ConsistOf(
				defaultTrustedCertBundle.Volume(),
				defaultTLSKeyPair.Volume(),
			))
			Expect(backend.VolumeMounts).To(HaveLen(len(defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux)) + 1))
			for _, o := range objsToCreate {
				_, isSecret := o.(*corev1.Secret)
				_, isConfigMap := o.(*corev1.ConfigMap)
				Expect(isSecret || isConfigMap).To(BeFalse(), "no key validator files rendered: %T %s", o, o.GetName())
			}
		})

		It("rolls the backend when the trusted bundle changes", func() {
			// A flow source's client may hold the bundle for the life of the
			// process, so a CA rotation must restart the pod.
			objsToCreate, _ := whisker.Whisker(backendOnlyConfiguration()).Objects()
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			for k, v := range defaultTrustedCertBundle.HashAnnotations() {
				Expect(deployment.Spec.Template.Annotations).To(HaveKeyWithValue(k, v))
			}

			// Whisker's own Goldmane client reloads the bundle, so the full
			// deployment is left alone.
			full := backendOnlyConfiguration()
			full.BackendOnly = false
			full.WhiskerKeyPair = defaultWhiskerKeyPair
			objsToCreate, _ = whisker.Whisker(full).Objects()
			deployment, err = rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			for k := range defaultTrustedCertBundle.HashAnnotations() {
				Expect(deployment.Spec.Template.Annotations).NotTo(HaveKey(k))
			}
		})

		It("keeps the Goldmane egress rule when the UI is deployed", func() {
			cfg := backendOnlyConfiguration()
			cfg.BackendOnly = false
			cfg.WhiskerKeyPair = defaultWhiskerKeyPair
			objsToCreate, _ := whisker.Whisker(cfg).Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, whisker.WhiskerPolicyName, whisker.WhiskerNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Egress[0].Destination.Selector).To(Equal(networkpolicy.KubernetesAppSelector(whisker.GoldmaneDeploymentName)))
			Expect(np.Spec.Egress[0].Destination.Ports).To(Equal(networkpolicy.Ports(whisker.GoldmaneServicePort)))
		})
	})

	Context("disabled", func() {
		It("creates nothing and removes whatever any configuration deployed", func() {
			cfg := backendOnlyConfiguration()
			cfg.BackendOnly = false
			cfg.Disabled = true
			// The controller issues no key pairs in this mode.
			cfg.WhiskerBackendKeyPair = nil

			objsToCreate, objsToDelete := whisker.Whisker(cfg).Objects()
			Expect(objsToCreate).To(BeEmpty())

			// Both shapes whisker can take are named, so a cluster that changed
			// shape before being disabled is cleaned up too.
			for _, want := range []struct {
				name string
				obj  client.Object
			}{
				{whisker.WhiskerServiceAccountName, &corev1.ServiceAccount{}},
				{whisker.WhiskerDeploymentName, &appsv1.Deployment{}},
				{"whisker-nginx-config", &corev1.ConfigMap{}},
				{whisker.WhiskerName, &corev1.Service{}},
				{whisker.WhiskerPolicyName, &v3.NetworkPolicy{}},
			} {
				found := false
				for _, o := range objsToDelete {
					if o.GetName() == want.name && reflect.TypeOf(o) == reflect.TypeOf(want.obj) {
						found = true
					}
				}
				Expect(found).To(BeTrue(), "%T %s should be deleted", want.obj, want.name)
			}

			// Pull secret copies are shared with other components and stay.
			for _, o := range objsToDelete {
				if sec, ok := o.(*corev1.Secret); ok {
					Expect(sec.Name).NotTo(Equal("pull-secret"))
				}
			}
		})

		It("resolves no images, so an ImageSet without the UI image is fine", func() {
			cfg := backendOnlyConfiguration()
			cfg.BackendOnly = false
			cfg.Disabled = true
			is := &operatorv1.ImageSet{Spec: operatorv1.ImageSetSpec{Images: []operatorv1.Image{
				{Image: "calico/calico", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			}}}
			Expect(whisker.Whisker(cfg).ResolveImages(is)).To(Succeed())
		})

	})

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

	It("should add a gateway ingress rule to the NetworkPolicy when the ingress gateway is configured", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:       defaultTrustedCertBundle,
			WhiskerKeyPair:          defaultWhiskerKeyPair,
			WhiskerBackendKeyPair:   defaultTLSKeyPair,
			Whisker:                 &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			IngressGatewayNamespace: "gateway-ns",
		}
		objsToCreate, _ := whisker.Whisker(cfg).Objects()
		var policy *v3.NetworkPolicy
		for _, obj := range objsToCreate {
			if p, ok := obj.(*v3.NetworkPolicy); ok && p.Name == whisker.WhiskerPolicyName {
				policy = p
			}
		}
		Expect(policy).NotTo(BeNil())
		Expect(policy.Spec.Ingress).To(HaveLen(1))
		rule := policy.Spec.Ingress[0]
		// kubernetes.io/metadata.name, not projectcalico.org/name: the latter is
		// applied by Calico's namespace controller, which does not run on every
		// dataplane (see #5151).
		Expect(rule.Source.NamespaceSelector).To(Equal("kubernetes.io/metadata.name == 'gateway-ns'"))
		Expect(rule.Source.Selector).To(Equal("gateway.envoyproxy.io/owning-gateway-name == 'calico-whisker-gateway'"))
		Expect(rule.Destination.Ports).To(Equal(networkpolicy.Ports(uint16(whisker.WhiskerServicePort))))

		// Without the gateway, Whisker stays deny-all.
		cfg.IngressGatewayNamespace = ""
		objsToCreate, _ = whisker.Whisker(cfg).Objects()
		for _, obj := range objsToCreate {
			if p, ok := obj.(*v3.NetworkPolicy); ok && p.Name == whisker.WhiskerPolicyName {
				Expect(p.Spec.Ingress).To(BeEmpty())
			}
		}
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

// backendOnlyConfiguration is the configuration a variant that serves the UI
// elsewhere renders from: no UI key pair, BackendOnly set.
func backendOnlyConfiguration() *whisker.Configuration {
	return &whisker.Configuration{
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
			Variant:            operatorv1.Calico,
		},
		TrustedCertBundle:     defaultTrustedCertBundle,
		WhiskerBackendKeyPair: defaultTLSKeyPair,
		Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		ClusterDomain:         "cluster.domain",
		BackendOnly:           true,
	}
}
